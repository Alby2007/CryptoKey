# Reference

## CLI

```console
cryptokey                        # dashboard app: guard + UI (add --dev, --takeover, --classic)
cryptokey guard                  # tray daemon, console hidden (same flags)
cryptokey enroll                 # enroll the inserted removable drive (failsafe passphrase, min 8
                                 # chars); also creates the Start Menu + Desktop shortcuts
cryptokey open                   # raise the dashboard on the running guard
cryptokey status                 # local verify + guard reachability
cryptokey lock                   # IPC: lock now
cryptokey pause [mins]           # IPC: pause auto-lock (default 5; works while paused to extend)
cryptokey resume                 # IPC: end a pause
cryptokey quit                   # IPC: stop the guard (refused while locked)
cryptokey help                   # usage
```

Hidden/infrastructure modes:

```console
cryptokey --set-startup <Off|Normal|Elevated>   # elevated startup helper (UAC helper target)
cryptokey --lock-watchdog <pid>                 # dead-man's switch spawned per secure engage
cryptokey watchdog --parent <pid>               # persistent guard supervisor (spawned by the guard)
cryptokey --release-desktop                     # SwitchDesktop → Default escape hatch
cryptokey --export-icon <path>                  # dev/internal: regenerate app.ico
```

Flags: `--dev` enables the panic exit combo `Ctrl+Alt+Shift+F12`;
`--takeover` waits on the guard mutex (elevated restart handoff);
`--classic` forces the overlay lock for that launch.

`status` exit code: 0 when the keyfile verifies (including previous-gen),
non-zero otherwise. `status` output includes `Unlock policy` and
`Lock mode` lines, and a `Guard:` line when the daemon answers the pipe.

## IPC protocol — `\\.\pipe\cryptokey-ctl`

One UTF-8 line per connection → one line back. Connect 1.5 s, server-side
read timeout ~5 s.

| Command | Reply | Rules |
|---|---|---|
| `lock` | `ok locked` | Locks immediately |
| `pause [mins]` | `ok paused until HH:mm` / `err …` | Unlocked or Paused only; re-pause extends |
| `resume` | `ok resumed` / `err not paused` | |
| `quit` | `ok quitting` / `err locked — …` | Refused while Locked (silent-unlock guard) |
| `reenrolled` | `ok re-enrolled` | Sent by `enroll`; guard reloads config in place + retargets the monitor |
| `status` | `ok state=… key=… model=… verifyFail=… pausedUntil=… tamper=… keyVerified=… policy=… watchdog=…` | `watchdog=alive/down` — supervisor liveness |
| `open` | `ok opened` | Raises the dashboard — routed before `DispatchCommand` |

Security: DACL grants `GA` to the owning user's SID; a medium-integrity
SACL label (`SE_SECURITY_PRIVILEGE` permitting) lets the normal CLI reach
an elevated guard while excluding low-IL processes.

## `config.json` — `%APPDATA%\CryptoKey\config.json`

Atomic writes: tmp → `FlushFileBuffers` → rename, so a torn write can never
land at the final name (matters most on FAT32/exFAT drives with no journal).
`config.json.bak` mirrors every save — a corrupt primary is quarantined to
`.bad` and the backup loads instead. Secrets are **hashes only** — the raw secret
lives only on the drive.

| Field | Meaning |
|---|---|
| `DeviceSerial` | WMI `Win32_DiskDrive` serial of the enrolled drive |
| `SecretSalt` + `SecretHash` | `SHA-256(salt ‖ secret)` verifier — base64 |
| `PrevSecretHash` | Previous ratchet generation (heal window) |
| `RotationCount`, `LastRotationUtc` | Ratchet bookkeeping; `status`/dashboard show generation |
| `PassphraseSalt` + `PassphraseHash` | PBKDF2-HMAC-SHA256 verifier — iteration count stored in `PassphraseIterations`: 600 000 written now, legacy 100 000 verifies until the next change |
| `PassphraseIterations` | PBKDF2 rounds for the hash above — persisted so old hashes keep verifying and upgrades ride the next `ChangePassphrase` |
| `Guard.PollIntervalMs` | USB poll cadence — default 1000, clamped 250–10 000 |
| `Guard.LockOnRemoval` | Auto-lock when the key disappears — default `true` |
| `Guard.BalloonTips` | Tray notifications — default `true` |
| `Guard.Animations` | Dashboard/lock animations — default `true` |
| `Guard.UnlockPolicy` | `KeyOrPassphrase` (default) · `KeyAndPassphrase` · `KeyOnly` — enum-as-string |
| `Guard.StrictTamper` | Stale keyfiles never count as the key factor — default `false` |
| `Guard.LockMode` | `"secure"` (default) · `"overlay"` — anything else → secure (fail-closed parse) |
| `Guard.Watchdog` | Persistent supervisor process — default `true`. Off → stands it down and keeps it down |
| `Guard.LockPolicies` | Hide Task Manager/sign-out/power affordances while locked — default `true`. Priors (any registry kind) backed up to `lockpolicies.json`, restored verbatim on unlock |

## Keyfile — `<drive>:\.cryptokey`

Hidden+system, written flushed-tmp→rename per letter on rotation.

```text
v2:  "CKY2" ‖ DPAPI-CurrentUser( secret 64B ‖ attestation 32B )
v1:  secret 64B  (legacy — verifies as pre-attestation, upgrades on rotation)
attestation = HMAC-SHA256(secret, "CKY-ATTEST" ‖ serial ‖ PassphraseHash)
```

## Logs — `%APPDATA%\CryptoKey\guard.log` + `watchdog.log`

Append-only, rotated to `.1` at ~256 KB, fail-safe (a logging error can
never take the process down). Persistent lines are timestamped
`[MM-dd HH:mm:ss]`; the dashboard seeds the last 60 `guard.log` lines and
renders live entries `[HH:mm:ss]`. The supervisor writes its own
`watchdog.log` — heartbeats, respawns, and stand-downs live there.

## Startup modes

| Mode | Registration | Notes |
|---|---|---|
| `Off` | — | Default; machine is unprotected after boot |
| `Normal` | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\CryptoKey` → `cryptokey.exe guard` | Writes need no elevation |
| `Elevated` | Scheduled task `CryptoKey`, `/rl highest`, at logon | Stronger lock (hooks can reach elevated windows' input path); toggling spawns the `--set-startup` helper — one UAC prompt |

`GetMode` validates *content*: the task must be enabled with a live exe
path; the Run value's embedded exe must exist. Stale registrations read
as `Off` rather than lying about protection.

The startup entries point at the exe path at registration time — moving
the binary dead-ends them (re-toggle in Settings to repair). Same for the
Start Menu `CryptoKey.lnk` shortcut.

## Files & named objects

| Object | Identity |
|---|---|
| Config / log dir | `%APPDATA%\CryptoKey\` |
| Keyfile | `<drive>:\.cryptokey` (+ `.tmp` transient) |
| Mutex | `Local\CryptoKeyGuard` |
| Pipe | `\\.\pipe\cryptokey-ctl` |
| Secure desktop | `WinSta0\CryptoKeyLock` |
| Run value | `HKCU\...\Run\CryptoKey` |
| Scheduled task | `CryptoKey` |
| Start Menu shortcut | `CryptoKey.lnk` |
| Desktop shortcut | `CryptoKey.lnk` on `DesktopDirectory` (follows OneDrive redirection) |
| App icon | `app.ico` — embedded via `ApplicationIcon`; every `.lnk` inherits it |
