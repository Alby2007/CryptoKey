# CryptoKey

Turn any USB flash drive into a physical PC key. Pull it out and a fullscreen
lock swallows your screen, keyboard, and mouse; plug it back in — or type the
failsafe passphrase — to unlock.

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
- **Lock** = one borderless topmost dark overlay per monitor (topmost
  re-asserted every 250 ms), low-level keyboard + mouse hooks that swallow all
  input, and `ClipCursor`. The keyboard hook feeds the passphrase buffer before
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
- **Ctrl+Alt+Del cannot be blocked** from user mode — Task Manager can kill the
  process. This is a deterrent, not a security boundary.
- Elevated windows (e.g. admin Task Manager) resist the input hooks — and the
  **On-Screen Keyboard** (UIAccess privilege) bypasses the keyboard hook
  entirely, so an attacker who opens OSK first can type freely.
- Some cheap drives report blank/duplicate serial numbers; enroll warns but
  allows it.
- The serial + keyfile can theoretically be spoofed with firmware tools.
- Auto-start is opt-in (Settings → Start with Windows). Until enabled, the PC
  is unprotected after a fresh boot.
