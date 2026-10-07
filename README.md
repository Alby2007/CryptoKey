# CryptoKey

Turn any USB flash drive into a physical PC key. Pull it out and a fullscreen
lock swallows your screen, keyboard, and mouse; plug it back in — or type
your recovery phrase — to unlock.

> **Internals:** architecture, security model, state machine, recovery
> paths, and the CLI/config reference live in [`docs/`](docs/README.md).

## How it works

- **Enroll** records the drive's hardware `SerialNumber` (via WMI, immune to
  drive-letter changes), writes a 64-byte random secret to `<drive>:\.cryptokey`,
  generates a 20-character **recovery phrase** (shown once — write it down),
  and stores salted hashes of the secret and the phrase in
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
  `HMAC-SHA256(secret, serial || passphraseHash || guard-canon)` — the canon
  covers the security-relevant settings (unlock policy, watchdog, strict
  tamper, vault flags, alert URL, …), so hand-editing `config.json` to weaken
  them is itself a tamper event: announce once (badge + log + snap + alert),
  then the envelope re-binds to the live config. In-app saves heal silently.
  Legacy raw keyfiles self-upgrade on next rotation.
- **Unlock policy** (Settings → Unlock policy): `Key or phrase` (default),
  `Key + phrase` (2FA — a verified key alone stays locked; a recovery phrase
  with no verified key is denied; **lost key = real lockout** — dev panic or
  Task Manager only), `Key only` (recovery phrase disabled). Strict tamper
  mode makes stale keyfiles never count as the key factor.
- **Recovery-phrase backoff** — fails 1-2 are free, then input freezes
  15s/30s/60s/120s/300s (enforced inside the keyboard hook, so mashing can't
  pile up attempts; countdown shown on the lock screen).
- **Lock** has two surfaces, chosen by Settings → *Lock on a private desktop*
  (or `config.json → Guard.LockMode`):
  - **secure** (default) — a private Windows desktop (`CreateDesktop`) the
    session is switched onto via `SwitchDesktop`. Only the lock card exists
    there: no taskbar, no windows, nothing to steal focus. Task Manager is
    policy-disabled while locked *because* launching it from Ctrl+Alt+Del
    would switch you back to the Default desktop — the SAS is the one path
    the private desktop can't isolate, so the policies seal it. The input hooks
    still run on a dedicated lock thread to feed the phrase buffer, and a
    flap monitor polls the input desktop every ~300 ms — a foreign desktop
    gets yanked back instantly, and 3 flaps inside 10 s escalates to
    `LockWorkStation` + alert + snapshot. If engagement fails at any step,
    the guard falls back to the overlay below.
  - **overlay** — the classic surface: one borderless topmost dark overlay
    per monitor (topmost re-asserted every 250 ms) on your own desktop,
    low-level keyboard + mouse hooks that swallow all input, and
    `ClipCursor`.
  In both modes the keyboard hook feeds the phrase buffer before
  swallowing, so the recovery phrase works while input is blocked.
- **IPC** — `lock` / `pause` / `resume` / `status` / `quit` reach the running
  guard over `\\.\pipe\cryptokey-ctl` (one line in, one line out; `quit` is
  refused while locked).
- **Tripwires** (Settings → Tripwires & alerts, all off by default): lock
  after N idle minutes via `GetLastInputInfo`; webcam still on tamper events
  (bad phrase, clone flag, break-glass) into `captures/` as DPAPI-sealed
  `.cap` files — only this app on this user can view them; and remote
  alerts — every lock/unlock/tamper event POSTs to your ntfy.sh topic or
  any webhook. The camera and the endpoint are opt-in, nothing leaves the
  machine otherwise. With idle lock on, a balloon warns ~20 s before it
  fires so the lock doesn't feel arbitrary.
- **Sound cues** — a synthesized low thunk on lock, a two-note chime on
  unlock, and a triple blip for tamper storms (Settings → "Lock/unlock
  sound cues", on by default). The cues are generated PCM, not shipped WAVs.
- **Encrypted vault** — a single `vault.ckv` image (AES-256-GCM chunks,
  filenames sealed in an authenticated manifest) that mounts as a real
  drive letter via Dokany **only while the key is in**: pull the key and
  it force-dismounts with every secret buffer zeroed. There is no vault
  passphrase — the device secret is the only factor, and its two key
  slots ride the rotation ratchet so a cloned keyfile unseals it for at
  most one generation. An optional idle seal (`VaultIdleMinutes`) dismounts
  it when the session goes idle and remounts when you're back, and a
  monotonic manifest epoch fences against a swapped-in older image —
  anything stale waits for your explicit `vault accept-rollback`. Optional
  **TPM binding** (`vault tpm-bind`) wraps a machine pepper under the TPM
  so a copied image + cloned keyfile won't open on any other machine —
  the recovery phrase is the hatch (`vault recover`), or `--strict` for
  no hatch at all. Vault tab → Create. Requires the Dokany driver; the app
  reports honestly when it's absent. (`cryptokey vault …` for the CLI verbs.)
- **Signed auto-update** — checks GitHub Releases at startup + daily for a
  newer build. Nothing installs itself: an update only applies when you
  click Install (About tab) or run `cryptokey update --apply`, and never
  while the session is locked. Releases carry an ECDSA-signed manifest
  verified against a key pinned in the binary — a compromised repo alone
  can't push a payload — and the swap keeps the previous install as
  `CryptoKey.prev` for rollback.

## Usage

```console
cryptokey               # launch the app: dashboard window + tray + guard
cryptokey enroll        # register a USB drive as your key
cryptokey unenroll      # remove the key binding — phrase-verified; the install,
                        # account, and phrase stay, auto-lock disarms until re-enroll
cryptokey guard --dev   # tray only: lock the PC while the key is absent
cryptokey open          # raise the dashboard of a running guard
cryptokey status        # enrollment + key presence + live guard state
cryptokey lock          # ask the running guard to lock now
cryptokey pause 10      # pause auto-lock for 10 minutes (default 5)
cryptokey resume        # end a pause early
cryptokey quit          # stop the running guard (refused while locked)
cryptokey update        # check for a newer signed release; --apply installs it
cryptokey auth status   # account gate state (signed in / locked / unenrolled)
```

Flags:

```console
--classic               # force the overlay lock (skip the private desktop)
--release-desktop       # escape hatch: switch input back to your desktop if
                        # the session ever strands on the lock desktop
```

**Try the attack yourself:** lock the PC, run `cryptokey --release-desktop`
— it warns that the guard is alive, switches anyway, and the flap monitor
yanks input back to the lock inside ~300 ms (logged as `desktop-flap`).
Three tries inside ten seconds and the session lands on the Windows
sign-in screen (`LockWorkStation`), which a script can't answer. The
hatch exists for dead-guard strands — a live guard treats it as a hostile
desktop switch.

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
`cryptokey --release-desktop` does the desktop rescue by hand (and restores
lock policies) — run it from another logged-in session (Ctrl+Alt+Del →
Switch user) or via Win+R after a reboot. Task Manager's "Run new task"
is *not* a hatch while locked — lock policies disable it by design, since
CAD → Task Manager is exactly the kill path they exist to close.
Disable the supervisor in Settings → "Watchdog process".

Double-clicking `cryptokey.exe` launches the dashboard (the console hides
itself when there's no shell attached). Closing the window hides to the
tray — the guard keeps running.

Run `cryptokey install` to copy the app to `%LOCALAPPDATA%\CryptoKey` and
repoint the Start Menu/Desktop shortcuts (and any armed autostart) at that
fixed path — this is what makes the shortcuts and Start-with-Windows
survive a `dotnet clean` of the build tree. If a guard is running it
offers a live handoff: the installed copy spawns with `--takeover`, the
old guard quits, and the new one claims the mutex with no unguarded gap.

The Settings tab has a **Start with Windows** toggle that registers
`cryptokey.exe guard` (tray-only, no window) in your per-user Run key —
it stores the running exe's path, so run it from the installed copy. The
**Launch as administrator** sub-toggle registers a
Scheduled Task with highest privileges instead (one UAC prompt when you
enable it) so the lock covers elevated windows too; **Restart as admin**
elevates the running instance in place. The Storage card can add/remove
Start Menu and Desktop shortcuts (enrollment creates both automatically),
and the dashboard activity feed persists to
`%APPDATA%\CryptoKey\guard.log` (rotated at 256 KB).

Tray menu: **Lock now**, **Pause auto-lock ▸** (5/15/60 min), **Resume**,
**Settings…** (key info, recovery phrase, poll interval, balloon tips),
**Quit** — enabled only while *unlocked*. While locked the ways out are
the key, the recovery phrase, or — as last resorts — Ctrl+Alt+Del → Switch user
or the power button (Task Manager and Sign out are policy-disabled by
design while locked).

`--dev` enables the emergency exit combo **Ctrl+Alt+Shift+F12**.
**Always use `--dev` during development and testing.**

## Account (optional cloud identity)

A **Supabase Auth** account (email + password) is the master switch: it
gates the dashboard, the sensitive commands — pause/resume/quit, vault
mutators, `update apply`, in-app settings — **and the auto-lock machinery
itself**. Signed out, a key pull is just a USB event; signed in, the key
locks the machine the moment it leaves. Unlocking is never gated — the
USB key and recovery phrase always open a locked PC, and manual `lock`
always works. See [`docs/auth.md`](docs/auth.md) for the full model.

Setup: drop `supabase.json` beside the exe (copy `supabase.example.json`)
with your project's `projectUrl` and **anon** key — the anon key is meant
to ship in clients; CryptoKey uses GoTrue auth only, no tables/RLS.
Under Auth → URL Configuration add the `cryptokey://recover` redirect so
password-reset emails deep-link back into the app.

- **First run** shows the create-account screen before the wizard; a
  signed-in account enrolls into `config.json` via a pending staging file.
- **Offline grace**: after one online sign-in, the same password unlocks
  the dashboard while offline — a local PBKDF2 verifier in the
  keyfile-attested config (grafting a foreign verifier trips the next key
  verify and refuses the password path entirely).
- **Sessions** persist in `session.dat` (DPAPI/Keychain-sealed); bearer
  tokens refresh automatically and expire gracefully.
- **CLI**: a gated verb answers `AUTH_REQUIRED`; retry prompts for the
  account password masked — it rides the pipe as a `|auth` trailer and is
  never logged, persisted, or placed on argv.
- **`cryptokey auth status`** reports the gate; **Account** page in the
  dashboard has sign-out, change password, and relink.

## macOS

The same security model runs on macOS via `src/CryptoKey.Mac` (Avalonia UI)
— enroll/status/lock/pause/resume/quit/guard are identical, and the lock is
`CGDisplayCapture` + a session event tap + per-screen shielding windows
instead of a private desktop. The keyfile is wrapped by a Keychain-held
AES-GCM key rather than DPAPI; autostart is a per-user LaunchAgent.

```bash
dotnet build src/CryptoKey.Mac/CryptoKey.Mac.csproj -c Release
./src/CryptoKey.Mac/bin/Release/net9.0/cryptokey uitest      # 3s lock smoke
./src/CryptoKey.Mac/bin/Release/net9.0/cryptokey enroll      # same flow
./src/CryptoKey.Mac/bin/Release/net9.0/cryptokey             # guard (UI tier)
./src/CryptoKey.Mac/bin/Release/net9.0/cryptokey install     # ~/Applications + LaunchAgent
```

The event tap needs **Accessibility** permission — without it a lock
attempt fails closed onto the real macOS lock screen. Full mapping,
publish profiles, and limits: [`docs/macos.md`](docs/macos.md).

## Build

```console
dotnet build                   # Core + both hosts (Win needs net9.0-windows)
dotnet test                    # xUnit suite — pure security invariants
dotnet run --project src/CryptoKey.Win -- enroll    # Windows host
dotnet run --project src/CryptoKey.Mac -- enroll    # macOS host
```

Enroll **generates** your recovery phrase — 20 Crockford Base32 characters
(`XXXXX-XXXXX-XXXXX-XXXXX`, ~100 bits, no ambiguous glyphs) — shows it
once, and asks you to retype it. Case, dashes, and O/0 or I-L/1 slips are
forgiven on entry. It's the failsafe when the key isn't available, and the
Key & Recovery page can regenerate it — authorized either by the current phrase
or by a verified enrolled key. Upgraded installs: **legacy passphrases no
longer verify** — attach your enrolled key and regenerate the phrase on
the Key & Recovery page. (Under `Key + phrase` the old passphrase can't unlock
at all, so the Key & Recovery page is unreachable — run `cryptokey enroll` from
another logged-in session to migrate.) If the drive's keyfile is ever
wiped, the Key & Recovery page's **Repair keyfile** button re-arms it —
deliberately user-gated rather than automatic.

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
  that's what `cryptokey --release-desktop` is for (it also restores lock
  policies; a CAD-power reboot always clears a stranded private desktop
  since desktop objects die with the session).
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
  until the guard next starts and restores. Plan accordingly while
  locked: Switch user and the power button remain, Task Manager and
  Sign out do not.
- `config.json` survives on three surfaces: `config.json.bak` mirrors every
  save (corrupt primary → `.bad` quarantine + backup load with a modal
  warning), and `HKCU\Software\CryptoKey\Config` holds a third copy — a
  wiped config *folder* restores from the registry and logs it as a tamper
  event.
- A running guard rewrites `config.json` on every rotation — kill the guard
  (`cryptokey quit`) before editing it by hand, or your edits are lost.
- Auto-start is opt-in (Settings → Start with Windows). Until enabled, the PC
  is unprotected after a fresh boot.
