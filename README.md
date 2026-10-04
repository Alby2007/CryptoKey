# CryptoKey

Turn any USB flash drive into a physical PC key. Pull it out and a fullscreen
lock swallows your screen, keyboard, and mouse; plug it back in — or type the
failsafe passphrase — to unlock.

> **Internals:** architecture, security model, state machine, recovery
> paths, and the CLI/config reference live in [`docs/`](docs/README.md).

## How it works

- **Enroll** records the drive's hardware `SerialNumber` (via WMI, immune to
  drive-letter changes), writes a 64-byte random secret to `<drive>:\.cryptokey`,
  and stores salted hashes of the secret and your failsafe passphrase in
  `%APPDATA%\CryptoKey\config.json`.
- **Guard** watches `WM_DEVICECHANGE` (with a 1s poll fallback). Key absent →
  lock; key present → verify serial + keyfile hash → unlock. It lives in the
  system tray with a state-colored padlock (green = unlocked, red = locked,
  amber = paused), a dark context menu, and a settings window.
- **Rolling keyfile** — every verified key session burns the secret and writes
  the next generation (config keeps the previous hash so an interrupted
  rotation heals). A replayed old secret still unlocks but logs a "possible
  clone" tamper warning and re-poisons itself.
- **Keyfile v2 envelope** — `.cryptokey` is `"CKY2" || DPAPI(secret ||
  attestation)`, bound to this user+machine via DPAPI (`CurrentUser`). Copies
  of the file are dead weight off this machine. The embedded attestation is
  `HMAC-SHA256(secret, serial || passphraseHash)` — if config.json's serial or
  passphrase hash is tampered with, the drive itself calls it out (tamper
  badge + log; the secret still verifies — tripwire, not gate). Legacy raw
  keyfiles self-upgrade on next rotation.
- **Unlock policy** (Settings → Unlock policy): `Key or passphrase` (default),
  `Key + passphrase` (2FA — a verified key alone stays locked; passphrase with
  no verified key is denied; **lost key = real lockout** — dev panic or Task
  Manager only), `Key only` (passphrase disabled). Strict tamper mode makes
  stale keyfiles never count as the key factor.
- **Passphrase backoff** — fails 1-2 are free, then input freezes
  15s/30s/60s/120s/300s (enforced inside the keyboard hook, so mashing can't
  pile up attempts; countdown shown on the lock screen).
- **Lock** has two surfaces, chosen by Settings → *Lock on a private desktop*
  (or `config.json → Guard.LockMode`):
  - **secure** (default) — a private Windows desktop (`CreateDesktop`) the
    session is switched onto via `SwitchDesktop`. Only the lock card exists
    there: no taskbar, no windows, nothing to steal focus, and Task Manager
    can't see the lock UI (it lives on a different desktop). The input hooks
    still run on a dedicated lock thread to feed the passphrase buffer. If
    engagement fails at any step, the guard falls back to the overlay below.
  - **overlay** — the classic surface: one borderless topmost dark overlay
    per monitor (topmost re-asserted every 250 ms) on your own desktop,
    low-level keyboard + mouse hooks that swallow all input, and
    `ClipCursor`.
  In both modes the keyboard hook feeds the passphrase buffer before
  swallowing, so the failsafe works while input is blocked.
- **IPC** — `lock` / `pause` / `resume` / `status` / `quit` reach the running
  guard over `\\.\pipe\cryptokey-ctl` (one line in, one line out; `quit` is
  refused while locked).

## Usage

```console
cryptokey               # launch the app: dashboard window + tray + guard
cryptokey enroll        # register a USB drive as your key
cryptokey guard --dev   # tray only: lock the PC while the key is absent
cryptokey open          # raise the dashboard of a running guard
cryptokey status        # enrollment + key presence + live guard state
cryptokey lock          # ask the running guard to lock now
cryptokey pause 10      # pause auto-lock for 10 minutes (default 5)
cryptokey resume        # end a pause early
cryptokey quit          # stop the running guard (refused while locked)
```

Flags:

```console
--classic               # force the overlay lock (skip the private desktop)
--release-desktop       # escape hatch: switch input back to your desktop if
                        # the session ever strands on the lock desktop
```

The secure lock runs the session on its own desktop — if CryptoKey is killed
or crashes while locked, Windows does NOT return input on its own, so two
watchdogs cover it. A tiny per-engage process (`--lock-watchdog <pid>`)
rides every secure lock: the moment the guard dies it switches input back
to your desktop itself. And a persistent supervisor (`cryptokey watchdog`)
heartbeats the guard over the control pipe: ~2 s after the guard dies it
releases any stranded desktop, calls `LockWorkStation` if the guard was
locked, and respawns `cryptokey guard` — while the guard respawns the
watchdog within ~5 s if *it* dies. Clean exits (quit, panic, takeover) set
a stand-down event so nothing respawns. As a manual layer,
`cryptokey --release-desktop` does the desktop rescue by hand — e.g. from
Task Manager's "Run new task" after Ctrl+Alt+Del, or the dev panic combo.
Disable the supervisor in Settings → "Watchdog process".

Double-clicking `cryptokey.exe` launches the dashboard (the console hides
itself when there's no shell attached). Closing the window hides to the
tray — the guard keeps running.

The Settings tab has a **Start with Windows** toggle that registers
`cryptokey.exe guard` (tray-only, no window) in your per-user Run key —
enable it from the exe you actually keep, since it stores the running
exe's path. The **Launch as administrator** sub-toggle registers a
Scheduled Task with highest privileges instead (one UAC prompt when you
enable it) so the lock covers elevated windows too; **Restart as admin**
elevates the running instance in place. The Storage card can add/remove
a Start Menu shortcut, and the dashboard activity feed persists to
`%APPDATA%\CryptoKey\guard.log` (rotated at 256 KB).

Tray menu: **Lock now**, **Pause auto-lock ▸** (5/15/60 min), **Resume**,
**Settings…** (key info, passphrase change, poll interval, balloon tips),
**Quit** — enabled only while *unlocked*. While locked the only ways out are
the key, the passphrase, or Task Manager.

`--dev` enables the emergency exit combo **Ctrl+Alt+Shift+F12**.
**Always use `--dev` during development and testing.**

## Build

```console
dotnet build
dotnet run --project src/CryptoKey -- enroll
```

## Warnings / known limits

- **Self-lockout is real.** Test only in `--dev` mode until you trust it.
- **Ctrl+Alt+Del cannot be blocked** from user mode — under the secure
  desktop the Ctrl+Alt+Del screen appears on the Default desktop, and Task
  Manager opened there can't see or reach the lock desktop. Killing the
  guard is fail-closed though: the watchdog releases the desktop, locks the
  workstation, and respawns it.
- **Killing ONE process doesn't stick — killing BOTH does.** The guard and
  watchdog respawn each other, but `taskkill /f /im cryptokey.exe` takes
  the pair down in one call. That's the user-mode ceiling — a deterrent,
  not a kernel boundary.
- A desktop-switch failure could strand the session on an empty desktop —
  that's what `cryptokey --release-desktop` is for (keep the command in mind).
- Elevated windows (e.g. admin Task Manager) resist the input hooks — and the
  **On-Screen Keyboard** (UIAccess privilege) bypasses the keyboard hook
  entirely, so an attacker who opens OSK first can type freely.
- Some cheap drives report blank/duplicate serial numbers; enroll warns but
  allows it.
- The serial + keyfile can theoretically be spoofed with firmware tools.
- DPAPI binds the keyfile to the enrolling Windows user + machine — a second
  user enrolling the same drive overwrites your envelope (single-slot file),
  and yours then fails to unwrap. One enrolled user per drive.
- While locked, HKCU policies hide Task Manager, Sign out/Switch user, and
  Start-menu power buttons — in overlay mode this closes the CAD →
  Task Manager → end-process kill path, the classic lock's main weakness.
  Priors (any registry kind) are backed up and restored verbatim on
  unlock. `taskkill`/Process Explorer still work, the Ctrl+Alt+Del power
  button can't be removed from user mode, and locked-down images
  (or GPO) that deny writes to `HKCU\...\Policies` mean partial/no
  coverage — run the guard elevated there. If the guard dies while
  locked (reboot, or a kill with the watchdog off) the policies persist
  until the guard next starts and restores.
- A running guard rewrites `config.json` on every rotation — kill the guard
  (`cryptokey quit`) before editing it by hand, or your edits are lost.
- Auto-start is opt-in (Settings → Start with Windows). Until enabled, the PC
  is unprotected after a fresh boot.
