# Reference

## CLI

```console
cryptokey                        # dashboard app: guard + UI (add --dev, --takeover, --classic)
cryptokey guard                  # tray daemon (same flags)
cryptokey enroll                 # enroll the inserted removable drive — generates the recovery
                                 # phrase (shown once, retyped to confirm); creates shortcuts
cryptokey open                   # raise the dashboard on the running guard
cryptokey status                 # local verify + guard reachability
cryptokey lock                   # IPC: lock now
cryptokey pause [mins]           # IPC: pause auto-lock (default 5; works while paused to extend)
cryptokey resume                 # IPC: end a pause
cryptokey quit                   # IPC: stop the guard (refused while locked)
cryptokey vault create [mb]      # create the encrypted image (IPC when a guard runs; needs the key in)
cryptokey vault status           # image state, key-slot generations, driver presence
cryptokey vault mount            # IPC: mount now (guard running); standalone: foreground mount, Enter dismounts
cryptokey vault unmount          # IPC: dismount now (guard running); standalone: driver-level unmount of the letter
cryptokey vault seal / unseal    # IPC: close the vault (drop the volume key — holds for the session) / reopen it
cryptokey vault delete           # delete the image entirely (IPC when a guard runs; destructive)
cryptokey vault accept-rollback  # ratify a vault image that reads older than the attested epoch
cryptokey vault tpm-bind [--strict]  # bind the image to this machine's TPM (prompts for the recovery phrase)
cryptokey vault tpm-unbind       # remove the machine binding (image opens anywhere again)
cryptokey vault recover          # unlock a TPM-locked vault with the recovery phrase
cryptokey install                # copy the payload to %LOCALAPPDATA%\CryptoKey and repoint
                                 # shortcuts + autostart at it; offers a live guard handoff
cryptokey update                 # check GitHub Releases for a newer signed build
cryptokey update --apply         # download + verify + install it (asks the live guard;
                                 # refused while locked)
cryptokey sign-release           # maintainer tooling: --gen-key <pem> |
                                 # <publishDir> <key.pem> [tag] → zip + signed manifest
cryptokey help                   # usage
```

`cryptokey.exe` is a GUI-subsystem binary — a desktop launch never creates a
console window. A verb run from a shell attaches to the parent's console for
output and prompts; interactive/output verbs launched without one (Run dialog,
shortcut) allocate a console on demand. Note PowerShell won't wait on a
GUI-subsystem exe — output still prints, the prompt just returns early.

Hidden/infrastructure modes:

```console
cryptokey --set-startup <Off|Normal|Elevated>   # elevated startup helper (UAC helper target)
cryptokey --lock-watchdog <pid>                 # per-engage dead-man's switch: parent gone → release input, then LockWorkStation
cryptokey watchdog --parent <pid>               # persistent guard supervisor (spawned by the guard)
cryptokey --release-desktop                     # SwitchDesktop → Default escape hatch
                                                # (while locked, the flap monitor yanks you back —
                                                # 3 tries in 10s escalates to LockWorkStation)
cryptokey --export-icon <path>                  # dev/internal: regenerate app.ico
cryptokey apply-update --target <dir>           # spawned by update apply from the staged
                                                # payload — quits the guard, swaps the
                                                # install dir, relaunches
```

Flags: `--dev` enables the panic exit combo `Ctrl+Alt+Shift+F12`;
`--takeover` waits on the guard mutex (elevated restart handoff);
`--classic` forces the overlay lock for that launch.

`status` exit code: 0 when the keyfile verifies (including previous-gen),
non-zero otherwise. `status` output starts with a `CryptoKey:` build line
(`0.9.0+<commit>` — compare the suffix against `git rev-parse HEAD` to
check the installed copy is current), then `Unlock policy`/`Lock mode`
lines, and a `Guard:` line when the daemon answers the pipe.

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
| `status` | `ok state=… key=… model=… verifyFail=… pausedUntil=… tamper=… keyVerified=… policy=… watchdog=… surface=… build=… elevated=… vault=… update=…` | `watchdog=alive/down` — supervisor liveness; `surface=secure/overlay` — active lock surface; `build` = running guard's version+commit; `elevated=yes/no` — guard integrity level; `update` = pending release tag or `-` |
| `update` / `update status` | `ok update v… pending …` / `ok up to date …` | Last check's result |
| `update check` | `ok checking` | Runs async — result lands on the next `status`/snapshot |
| `update apply` | `ok update applying …` / `err locked — …` / `err no update pending` | Refused while Locked; stages the signed payload then hands off to it — the staged `apply-update` quits the guard, swaps the install dir, relaunches |
| `vault status` | `ok vault state=… image=… exists=… driver=… mount=… idlemin=… epoch=… slots=… tpm=… used=… total=…` | state: `disabled`/`noimage`/`sealed`/`sealeddead`/`corrupt`/`needsdriver`/`unsealed`/`mounted`/`rolledback`/`tpmlocked`; `idlemin` = `VaultIdleMinutes`; `epoch` = attested manifest seq; `tpm` = `bound`/`-` |
| `vault tpm-bind <phrase> [--strict]` | `ok vault bound to this machine` / `err …` | Wraps the pepper under the TPM + seals a phrase-recovery blob (omitted under `--strict`); needs the vault unsealed |
| `vault tpm-unbind` | `ok vault unbound` / `err …` | Re-wraps slots pepperless + deletes the TPM key |
| `vault recover <phrase>` | `ok vault unlocked via recovery phrase` / `err …` | Opens a `tpmlocked` vault via the sealed recovery blob |
| `vault mount` / `vault unmount` | `ok mounted at V:\` / `ok unmounted` / `err …` | Mount needs the key in + driver present |
| `vault seal` / `vault unseal` | `ok vault sealed` / `ok vault unsealing` / `err …` | Seal dismounts AND drops the volume key — auto-open stays suppressed until a key event or `unseal` |
| `vault accept-rollback` | `ok vault re-synced` / `err …` | Ratifies a `rolledback` image — moves the attested epoch down to it and re-opens. Explicit user call only |
| `vault create [mb]` | `ok vault created` / `err …` | Needs the verified key; defaults to `VaultSizeMb` |
| `open` | `ok opened` | Raises the dashboard — routed before `DispatchCommand` |
| `deeplink <url>` | `ok` | Forwards a `cryptokey://` launch arg to the shell's deep-link handler — routed before `DispatchCommand` |
| `auth status` | `ok auth state=… email=… configured=…` | Read-only account-gate state: `unconfigured`/`unenrolled`/`locked`/`offlineunlocked`/`online` |
| `auth signout` | `ok signed out` | Ends the session (clears `session.dat`); gated like any mutator |

**Account gate** (see `docs/auth.md`): with an account bound, mutating
verbs — `pause`, `resume`, `quit`, `reenrolled`, `vault <mutator>`,
`update apply`, `auth signout` — answer `err AUTH_REQUIRED — …` unless
the request carries `|auth <base64 password>` or the session is already
unlocked. A correct trailer also arms the session for the rest of the
run. `lock`, `status`, `open`, `deeplink`, `auth status`, `vault status`,
and `update status`/`check` are always open (`lock` only makes the box
safer; reads disclose nothing).

Security: DACL grants `GA` to the owning user's SID; a medium-integrity
SACL label (`SE_SECURITY_PRIVILEGE` permitting) lets the normal CLI reach
an elevated guard while excluding low-IL processes.

## `config.json` — `%APPDATA%\CryptoKey\config.json`

Atomic writes: tmp → `FlushFileBuffers` → rename, so a torn write can never
land at the final name (matters most on FAT32/exFAT drives with no journal).
`config.json.bak` mirrors every save — a corrupt primary is quarantined to
`.bad` and the backup loads instead; a corrupt backup is quarantined to
`.bak.bad` and the chain falls through to the registry copy. Secrets are
**hashes only** — the raw secret lives only on the drive.

| Field | Meaning |
|---|---|
| `DeviceSerial` | WMI `Win32_DiskDrive` serial of the enrolled drive |
| `SecretSalt` + `SecretHash` | `SHA-256(salt ‖ secret)` verifier — base64 |
| `PrevSecretHash` | Previous ratchet generation (heal window) |
| `RotationCount`, `LastRotationUtc` | Ratchet bookkeeping; `status`/dashboard show generation |
| `PassphraseSalt` + `PassphraseHash` | PBKDF2-HMAC-SHA256 verifier over the normalized recovery phrase — iteration count stored in `PassphraseIterations`: 600 000 written now, legacy 100 000 verifies until the next change |
| `PassphraseIterations` | PBKDF2 rounds for the hash above — persisted so old hashes keep verifying and upgrades ride the next `ChangePassphrase` |
| `Guard.PollIntervalMs` | USB poll cadence — default 1000, clamped 250–10 000 |
| `Guard.LockOnRemoval` | Auto-lock when the key disappears — default `true` |
| `Guard.BalloonTips` | Tray notifications — default `true` |
| `Guard.Animations` | Dashboard/lock animations — default `true` |
| `Guard.Sounds` | Synthesized cues: lock thunk, unlock chime, tamper-storm alarm — default `true` |
| `Guard.UnlockPolicy` | `KeyOrPassphrase` (default) · `KeyAndPassphrase` · `KeyOnly` — enum-as-string |
| `Guard.StrictTamper` | Stale keyfiles never count as the key factor — default `false` |
| `Guard.LockMode` | `"secure"` (default) · `"overlay"` — anything else → secure (fail-closed parse) |
| `Guard.Watchdog` | Persistent supervisor process — default `true`. Off → stands it down and keeps it down |
| `Guard.LockPolicies` | Hide Task Manager/sign-out/power affordances while locked — default `true`. Priors (any registry kind) backed up to `lockpolicies.json`, restored verbatim on unlock |
| `Guard.IdleLockMinutes` | Lock after N minutes without input (`GetLastInputInfo`) — `0` = off (default). Fires only from Unlocked; Paused suppresses it. One warn (~20 s before, as a balloon) + one lock per idle streak — both re-arm only after input returns, so a present key's auto-unlock can't flap |
| `Guard.WebcamOnTamper` | Snapshot the webcam on tamper events (bad phrase, clone flag, break-glass) — `false` = off (default, privacy opt-in). Stills land in `captures/` as DPAPI-sealed `.cap` files (viewable only by this app on this user; legacy cleartext captures still render), trimmed to 50 |
| `Guard.AlertUrl` | POST endpoint for security events — ntfy.sh topic or any webhook; `""` (default) = off. Payload: `machine: event` text + `Title` header, 4 s timeout, fire-and-forget |
| `Guard.VaultEnabled` | Vault feature gate — default `false` until the first `vault create` (the Vault page enables it on create) |
| `Guard.VaultAutoMount` | Mount as soon as the key verifies — default `true` |
| `Guard.VaultImagePath` | Image location — default `%LOCALAPPDATA%\CryptoKey\vault.ckv` |
| `Guard.VaultMountPoint` | Drive letter — default `V:\`; free letters offered in the Vault page |
| `Guard.VaultSizeMb` | Image size used by `vault create` — default 256, range 64–8192 |
| `Guard.VaultIdleMinutes` | Seal the vault after N minutes without input — `0` = off (default). A mounted vault dismounts and drops its keys; the verify feed stays suppressed while idle, so it remounts when input returns |
| `Guard.UpdateCheckEnabled` | Check GitHub Releases at startup + daily for a newer signed build — default `true`. Notify-only: nothing installs without an explicit apply. Lifecycle class — outside the attestation canon |
| `VaultEpoch` | Highest vault manifest seq the keyfile has attested — the rollback fence's trusted witness. Managed automatically (synced on open/close/reformat); hand-editing it trips attestation, and setting it past the image flags `rolledback` |
| `Account` | The bound CryptoKey account — `UserId`, `Email`, `VerifierSalt`/`VerifierHash`/`VerifierIterations` (PBKDF2-SHA256, 600 000). Never a password or token — the verifier proves the app-side password offline; `session.dat` holds the bearer pair. Inside the attestation MAC (`\|accounthash=`), so grafting a foreign verifier trips the next key verify and refuses the password path |

`config.json` also mirrors into `HKCU\Software\CryptoKey\Config` (REG_SZ)
on every save — a third copy on a different kill surface. Load chain:
primary → `.bak` → registry (a registry restore rewrites both files and
is logged as a tamper event; the watchdog's respawn gate accepts any copy).
Consequence: deleting `%APPDATA%\CryptoKey` no longer resets CryptoKey —
a full reset is the folder **and** the `HKCU\Software\CryptoKey` key.

## Keyfile — `<drive>:\.cryptokey`

Hidden+system, written flushed-tmp→rename per letter on rotation.

```text
v2:  "CKY2" ‖ DPAPI-CurrentUser( secret 64B ‖ attestation 32B )
v1:  secret 64B  (legacy — verifies as pre-attestation, upgrades on rotation)
attestation = HMAC-SHA256(secret, "CKY-ATTEST2" ‖ serial ‖ PassphraseHash ‖ canon)
  canon = security Guard fields only — unlock policy, strict-tamper, lock
  mode, removal/watchdog/policies/idle-lock, webcam, alert URL, vault
  enabled/automount/idle, poll interval, vault epoch (cosmetic + layout
  fields excluded; pre-epoch canon and legacy "CKY-ATTEST" MACs still
  verify — reads accept all three forms, writes always emit the newest)
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

## Auto-update

GitHub Releases is the update channel — three assets per release:
`cryptokey-win-x64.zip` (payload), `SHA256SUMS.txt` (the signed manifest:
`# release: <tag>` + `<sha256>  <zip>`), `SHA256SUMS.sig` (ECDSA-P256 P1363
signature over the manifest bytes, maintainer key). The public key is
pinned in `ReleaseSigning.cs`; the private key lives only in the
`RELEASE_SIGNING_KEY` Actions secret / the maintainer's PEM — never in
the tree.

Chain of trust: HTTPS is transport only — acceptance requires (1) a
strictly newer tag (`v…` — `+build`/`-rc` stripped), (2) a manifest whose
signature verifies against the pinned key, (3) a `# release:` binding that
matches the tag (an older signed payload can't be re-served as newer),
(4) the zip's sha256 matching the manifest, (5) path-safe extraction.
Checks run at guard start + daily (`Guard.UpdateCheckEnabled`); an update
is notify-only — apply always needs an explicit click or
`cryptokey update --apply`, and it's refused while the session is locked.
Apply stages the payload under `CryptoKey-staging\`, spawns the staged
`apply-update`, which quits the guard, moves the install to
`CryptoKey.prev` (rollback net), moves the payload in, and relaunches.

Releasing: `git tag vX.Y.Z && git push origin vX.Y.Z` → `release.yml`
publishes, signs via `cryptokey sign-release` with the secret key, and
uploads the three assets. Bump `<Version>` first so the tag and the build
stamp agree.

## Files & named objects

| Object | Identity |
|---|---|
| Config / log dir | `%APPDATA%\CryptoKey\` |
| Keyfile | `<drive>:\.cryptokey` (+ `.tmp` transient) |
| Mutex | `Local\CryptoKeyGuard` |
| Pipe | `\\.\pipe\cryptokey-ctl` |
| Secure desktop | `WinSta0\CryptoKeyLock` (suffixed `-N` for process life when a squatter survives engage-time eviction) |
| Run value | `HKCU\...\Run\CryptoKey` |
| Scheduled task | `CryptoKey` |
| Registry config backup | `HKCU\Software\CryptoKey\Config` (REG_SZ, same JSON) |
| Tamper captures | `%APPDATA%\CryptoKey\captures\` (newest 50 kept) |
| Vault image | `%LOCALAPPDATA%\CryptoKey\vault.ckv` (default; `VaultImagePath` overrides) |
| Vault TPM key | persisted CNG key `CryptoKeyVault` in `Microsoft Platform Crypto Provider`, user-scoped |
| Update staging | `%LOCALAPPDATA%\CryptoKey-staging\update-<tag>\` (wiped per attempt) |
| Previous install | `%LOCALAPPDATA%\CryptoKey.prev` — kept as the update rollback net |
| Start Menu shortcut | `CryptoKey.lnk` |
| Desktop shortcut | `CryptoKey.lnk` on `DesktopDirectory` (follows OneDrive redirection) |
| App icon | `app.ico` — embedded via `ApplicationIcon`; every `.lnk` inherits it |

macOS equivalents: config/log dir `~/Library/Application Support/CryptoKey/`,
config backup `~/Library/Preferences/CryptoKey/config-backup.json`, flock
locks + `watchdog.stop` under that dir, unix socket `cryptokey-ctl.sock` under
`$TMPDIR`, LaunchAgent `~/Library/LaunchAgents/com.cryptokey.guard.plist`,
unix socket `cryptokey-ctl` under `$TMPDIR`,
