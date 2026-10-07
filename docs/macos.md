# macOS port — CryptoKey.Mac

The same Core, a Mac host. `src/CryptoKey.Mac` produces a `cryptokey`
binary that shares every security-relevant behavior with the Windows
app — enrollment, rolling keyfile, recovery phrase, backoff, watchdog —
and re-expresses the OS plumbing through `PlatformServices`.

## Requirements & permissions

- macOS, a `.NET 9` SDK for building (the published payload is
  self-contained — no runtime needed to *run* it).
- **Accessibility permission** — the event tap can't be created without
  it. The first `Engage` fails closed: `CGSession -suspend` drops you at
  the real OS lock, and the CLI prints where to grant it
  (System Settings → Privacy & Security → Accessibility). Grant it to the
  binary path you're actually running.
- Screen Recording is **not** needed — `CGDisplayCapture` doesn't read
  pixels, it just blanks.

## Build / run / test

```bash
dotnet build src/CryptoKey.Mac/CryptoKey.Mac.csproj -c Release
./src/CryptoKey.Mac/bin/Release/net9.0/cryptokey            # guard (UI tier)
./src/CryptoKey.Mac/bin/Release/net9.0/cryptokey --headless # capture+tap only
./src/CryptoKey.Mac/bin/Release/net9.0/cryptokey uitest     # 3s lock smoke
```

Publish (self-contained folder — single-file can't carry the Skia/
Avalonia dylibs; verified):

```bash
dotnet publish src/CryptoKey.Mac/CryptoKey.Mac.csproj -p:PublishProfile=osx-arm64
dotnet publish src/CryptoKey.Mac/CryptoKey.Mac.csproj -p:PublishProfile=osx-x64
# payload lands in bin/Publish/<rid>/
```

## Install

```bash
./cryptokey install     # copy payload → ~/Applications/CryptoKey,
                        # LaunchAgent → ~/Library/LaunchAgents, start now
./cryptokey uninstall   # bootout + remove the plist (binary stays)
```

The LaunchAgent (`com.cryptokey.guard`) runs `cryptokey guard` with
`RunAtLoad` + `LimitLoadToSessionType=Aqua` + `ProcessType=Interactive`,
logs to `~/Library/Logs/CryptoKey/`, and uses `KeepAlive={Crashed:true}` —
**launchd is the outer supervisor**: a signal-killed guard respawns, while
clean exits (`cryptokey quit`, unenrolled exit-1) stay dead. The in-app
watchdog is still the inner layer (pipe heartbeat, OS-lock on locked
death, stand-down on graceful exit); `flock` makes a double-spawn harmless.

## What maps to what

| Windows | macOS |
|---|---|
| WMI `Win32_DiskDrive` + `Win32_LogicalDisk` join | `/Volumes` → `statfs` BSD name → `DADiskCreateFromBSDName` description (removable + USB serial) |
| `WM_DEVICECHANGE` + 1s poll | 1s enumeration poll (no device-change event exists) |
| DPAPI `CurrentUser` envelope | AES-GCM wrap key in the login Keychain, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`; the keyfile `entropy` blob becomes AES-GCM AAD |
| `\\.\pipe\cryptokey-ctl` + DACL + integrity SACL | unix domain socket under `$TMPDIR` (per-user already) via `NamedPipeServerStream` |
| `Local\CryptoKey*` mutexes/events | `flock` files under the config dir + `watchdog.stop` stand-down file |
| HKCU registry third config copy | `~/Library/Preferences/CryptoKey/config-backup.json` |
| `CreateDesktop` private desktop + LL hooks | `CGDisplayCapture` + per-screen windows at `CGShieldingWindowLevel` + `CGEventTap` (session scope, eats all input) |
| Task-Manager lock policies | N/A — macOS has no equivalent attack surface under a captured display; fail-closed is `CGSession -suspend` |
| `LockWorkStation` | `CGSession -suspend` (then `pmset displaysleepnow`) |
| Run key / scheduled task | LaunchAgent (`~/Library/LaunchAgents/com.cryptokey.guard.plist`) |
| Webcam tamper stills | N/A (`NullCaptureService`) |
| `dotnet cryptokey.dll` dev runs | Watchdog respawn uses `Environment.ProcessPath` — under `dotnet` it would spawn `dotnet guard` wrongly; run the built apphost for a faithful guard |

## The lock

Engage order is **tap → capture → windows** — the cheap failure (no AX
permission) never blanks the screen. Phrase entry is identical to Windows:
the tap feeds a fixed 256-char buffer that gets wiped on every path;
the windows render dot counts and status text only, never characters.
`cryptokey uitest` engages the real surface for 3s without enrollment.

Unlock: reinsert the key (serial + keyfile verify, same ratchet) or type
the recovery phrase. `--dev` arms the panic combo `Ctrl+Opt+Shift+F12`
(debug builds only — Release ignores the flag).

## Not yet / won't

- **Dashboard/settings UI** — the tray menu (Lock/Pause/Resume/Status/
  Quit) is the only always-on surface; settings edit `config.json`.
- **`Guard.LockMode`** is honored as a config key but maps to the same
  capture+tap machinery — there is no overlay-vs-desktop split on macOS.
- **Keychain prompt on first protect** — the wrap key mints silently;
  macOS may ask to unlock the login keychain if it's not already.
