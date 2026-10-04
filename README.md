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
  lock; key present → verify serial + keyfile hash → unlock.
- **Lock** = one borderless topmost black overlay per monitor (topmost
  re-asserted every 250 ms), low-level keyboard + mouse hooks that swallow all
  input, and `ClipCursor`. The keyboard hook feeds the passphrase buffer before
  swallowing, so the failsafe works while input is blocked.

## Usage

```console
cryptokey enroll        # register a USB drive as your key
cryptokey guard --dev   # lock the PC while the key is absent
cryptokey status        # show enrollment + key presence
```

`--dev` enables the emergency exit combo **Ctrl+Alt+Shift+F12**.
**Always use `--dev` during development and testing** — otherwise the only ways
out are the enrolled key, the passphrase, or Task Manager.

## Build

```console
dotnet build
dotnet run --project src/CryptoKey -- enroll
```

## Warnings / known limits

- **Self-lockout is real.** Test only in `--dev` mode until you trust it.
- **Ctrl+Alt+Del cannot be blocked** from user mode — Task Manager can kill the
  process. This is a deterrent, not a security boundary.
- Elevated windows (e.g. admin Task Manager) resist the input hooks.
- Some cheap drives report blank/duplicate serial numbers; enroll warns but
  allows it.
- The serial + keyfile can theoretically be spoofed with firmware tools.
- v1 never auto-starts at boot.
