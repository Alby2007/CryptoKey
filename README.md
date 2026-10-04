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
- **Lock** = one borderless topmost dark overlay per monitor (topmost
  re-asserted every 250 ms), low-level keyboard + mouse hooks that swallow all
  input, and `ClipCursor`. The keyboard hook feeds the passphrase buffer before
  swallowing, so the failsafe works while input is blocked.
- **IPC** — `lock` / `pause` / `resume` / `status` reach the running guard over
  `\\.\pipe\cryptokey-ctl` (one line in, one line out, current-user ACL).

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
```

Double-clicking `cryptokey.exe` launches the dashboard (the console hides
itself when there's no shell attached). Closing the window hides to the
tray — the guard keeps running.

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
- v1 never auto-starts at boot.
