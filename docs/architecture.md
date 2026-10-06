# Architecture

## Process roles — one exe, several hats

`CryptoKey.exe` dispatches on `argv` before anything else happens. All roles
share the same binary and config (the diagram shows the Windows host —
[macos.md](macos.md) has the Mac equivalents):

```mermaid
flowchart TD
    A[cryptokey ...] --> B{argv}
    B -->|"bare / open"| GUI["Desktop app<br/>guard thread + Avalonia dashboard"]
    B -->|"guard"| GRD["Tray daemon<br/>guard only, console hidden"]
    B -->|"status / lock / pause / resume / quit"| CLI["CLI client<br/>one line over the pipe, exit"]
    B -->|"enroll"| ENR["Enroll CLI<br/>writes keyfile + config, pings guard"]
    B -->|"--set-startup"| SUH["Startup helper<br/>elevated schtasks/registry writes"]
    B -->|"--lock-watchdog pid"| WD["Lock watchdog<br/>waits on parent, restores desktop"]
    B -->|"watchdog --parent pid"| PWD["Supervisor watchdog<br/>heartbeats the pipe,<br/>respawns the guard"]
    B -->|"--release-desktop"| RD["Escape hatch<br/>SwitchDesktop → Default"]
```

Two important consequences:

- **Single instance.** The guard holds the `Local\CryptoKeyGuard` mutex.
  A second GUI launch doesn't start a second guard — it pipes `open` to the
  running one. `--takeover` waits on the mutex (up to ~30 s) for the
  elevated-restart handoff.
- **No service process.** The daemon is a WinExe with its console hidden;
  autostart launches `cryptokey.exe guard` via the Run key or a scheduled
  task.

## Component map

```mermaid
flowchart LR
    subgraph guard["Guard process"]
        direction TB
        GS["GuardService<br/>state machine + policy"]
        MON["UsbMonitor<br/>WMI poller"]
        IPC["IpcServer<br/>\\\\.\\pipe\\cryptokey-ctl"]
        SRF["ILockSurface"]
        KV["KeyVerifier<br/>envelope + hash checks"]
        CS["ConfigStore<br/>atomic config.json I/O"]
        TRAY["UiShell tray<br/>TrayIcon + flyout"]
        UI["CryptoKey.Ui<br/>Avalonia dashboard"]
        SUP["Supervisor<br/>mutex probe + spawn + stop"]
    end

    SUP -->|"spawn if mutex absent (~5s)<br/>set stop-event on clean exit"| PWD["cryptokey watchdog<br/>persistent supervisor"]
    PWD -->|"status heartbeat ~750ms<br/>respawn cryptokey guard"| IPC

    MON -- "presence / checked<br/>(marshaled to UI thread)" --> GS
    IPC -- "lock · pause · resume ·<br/>quit · status · reenrolled" --> GS
    GS --> SRF
    GS --> KV
    GS --> CS
    GS --> TRAY
    GS --> UI

    SRF --> SEC["SecureLockSurface<br/>private desktop + lock thread + watchdog"]
    SRF --> CLS["ClassicLockSurface<br/>LockScreen overlay + InputLocker hooks"]

    KV --- USB[("removable drive<br/>.cryptokey")]
    CS --- CFG[("%APPDATA%\\CryptoKey\\config.json")]
    MON --- WMI["WMI Win32_DiskDrive"]
    SEC --- DESK["desktop API<br/>CreateDesktop / SwitchDesktop"]
```

`GuardService` is the only stateful coordinator — everything else is a
device it drives. On Windows it now lives on its own engine thread; the
Avalonia front end talks to it through `GuardClient`, which marshals every
command/mutation onto the engine thread and hands back immutable snapshots
(`StatusSnapshot`/`SettingsView`).

## Threading model

| Thread | Owns | Rules |
|---|---|---|
| **Avalonia UI thread** | Dashboard, tray, flyout, wizard — `CryptoKey.Ui` | Never runs engine work; a UI exception is logged and windows close — the guard is unaffected |
| **Engine thread** (WinForms pump) | `GuardService`, monitor callbacks, config mutation, rotation bookkeeping | Must never block on USB I/O while hooks may be installed — rotation writes go to a worker |
| **WMI worker** (`UsbMonitor`) | `Win32_DiskDrive` enumeration | Polls off-pump so a slow WMI query can't stall hooks; results marshal to the engine thread |
| **Lock thread** (secure mode, per engage) | `SetThreadDesktop` → `InputLocker` LL hooks → `LockForm` → own message pump | STA. Created fresh every engage; teardown closes the form and joins |
| **Rotation worker** | `RotateKeyfiles` — pure file I/O on a pre-built envelope | Reads no mutable config; logs back via `BeginInvoke` |
| **Phrase worker** | PBKDF2 verify (600k iterations; count stored per-config) | Hook returns instantly; result marshaled back to UI; the char[] attempt is wiped after verify |
| **Lock-watchdog process** | `Process.WaitForExit(parent)` → `SwitchDesktop(Default)` | Per-engage, spawned before every secure switch, killed on clean disengage — covers the kill-both window while locked |
| **Supervisor watchdog process** | Pipe heartbeat (`status`) → release desktop → `LockWorkStation` → respawn `cryptokey guard` | Persistent, one per guard lifetime (`Local\CryptoKeyWatchdog` mutex); stands down on the `CryptoKeyWatchdogStop` event; killed watchdog is respawned by the guard's ~5 s liveness tick |

The invariant the whole design defends: **the thread that installs the
low-level hooks must pump** — anything that can stall a pump (WMI, USB
writes, PBKDF2) is pushed off it, because a stalled hook callback hits
`LowLevelHooksTimeout` and input leaks through unswallowed.

## Data stores

| Store | Location | Notes |
|---|---|---|
| `config.json` (+ `.bak` mirror, `.bad` quarantine) | `%APPDATA%\CryptoKey\` | Flushed tmp→rename writes (`FlushFileBuffers` before the rename); `.bak` mirrors every save — corrupt primary self-heals. Secret **hashes** only — the raw secret lives only on the drive |
| `guard.log` (+ `.1`) | `%APPDATA%\CryptoKey\` | Append-only activity log, rotated at ~256 KB, fail-safe (can never take the guard down) |
| `.cryptokey` | drive root, hidden+system | `"CKY2" ‖ DPAPI(secret ‖ attestation)` — bound to user+machine; flushed tmp→rename writes per letter |
| `cryptokey-ctl` | named pipe | Per-user DACL + medium-integrity SACL (see security-model); doubles as the watchdog's heartbeat |
| `Local\CryptoKeyGuard` | mutex | Single-instance + takeover handoff |
| `Local\CryptoKeyWatchdog` | mutex | One supervisor watchdog per session — spawned only when absent |
| `Local\CryptoKeyWatchdogStop` | named event (manual-reset) | Every graceful guard exit sets it — clean deaths never respawn |
| `watchdog.log` (+ `.1`) | `%APPDATA%\CryptoKey\` | Supervisor's own log — separate file, same 256 KB rotation |
| `lockpolicies.json` | `%APPDATA%\CryptoKey\` | Per-policy priors while locked — kind + raw value verbatim (legacy backups were plain `int?` and still load) — flushed tmp→rename; deleted on restore; a stale file self-heals at next `Start` |
| Registry config backup | `HKCU\Software\CryptoKey\Config` | Third config copy (same JSON, REG_SZ) — survives a folder wipe; Load falls through to it and rewrites the files |
| `captures\*.cap` | `%APPDATA%\CryptoKey\captures\` | Webcam tamper stills (opt-in) — DPAPI-sealed per user+machine, newest 50 kept |
| `vault.ckv` | `%LOCALAPPDATA%\CryptoKey\` (configurable) | CKVAULT1 encrypted volume image — dual header pages (checksummed) + dual manifest slots + AES-GCM chunks; session-scoped Dokan mount only while the key verifies. Manifest seq fences against the attested `VaultEpoch` — an older image gates at `RolledBack` until explicitly ratified |
| Registry / Task Scheduler | `HKCU\...\Run\CryptoKey`, task `CryptoKey` | Startup modes — validated by content, not just presence |

## Vault format — `CKVAULT1`

A single-file encrypted volume we own end-to-end. The image never carries
the device secret — only a random **volume key**, wrapped per key slot.
Everything is AES-256-GCM; every encrypted object authenticates its
location as AAD so ciphertext can't be relocated silently.

```text
header page (4 KiB) ×2 — primary at 0, identical shadow at 4096
  magic "CKVAULT\x01" | version u32 | flags u32 | salt 16B
  keySlot[2]:  { rotationGen u32 | nonce 12B | wrappedVolKey 48B }
  manifestSeq[2] u64 | chunkCount u32 | chunkRegionBase u64
  v3 extension (starts at the old @192 checksum offset):
    extLen u16 | tpmPepperBlob 256B | recPepperBlob 64B | recIters u32
    headerCheck 8B — truncated SHA-256 of page[0..518); a torn-but-plausible
                     primary rejects and the shadow carries the open
  (v2 images keep the @192 check and no extension — reads accept both;
   the next header write upgrades to v3 in place)
manifest slot A + slot B (4 MiB each, fixed)
  magic u32 | seq u64 | plainLen u32 | nonce 12B | tag 16B | ct
chunk region (fills the rest of the image)
  chunk i = nonce 12B | tag 16B | ct 4096B     (4124 B per 4 KiB chunk)
```

- **KEK** = `HMAC-SHA256(deviceSecret, "CryptoKeyVaultKEK" ‖ salt ‖ pepper)` —
  derived on demand, never stored, zeroed after use; an empty pepper is
  byte-identical to the v2 derivation.
- **Key slots** ride the keyfile ratchet: slot A wraps under the current
  generation, slot B under the previous — a stale-but-legit keyfile still
  unseals the vault inside the heal window. Each rotation edge rewraps
  `{cur, prev}`; two rotations without an open seals the image
  permanently (by design — the volume key is nowhere else).
- **Manifest** = JSON tree (paths → metadata + chunk ids + freelist),
  sealed with `(slot, seq)` AAD. Filenames are ciphertext — a stolen
  image reveals nothing. Flush alternates slots and bumps `seq`; a torn
  write falls back to the older decrypting epoch. On open the freelist
  is rebuilt from the node tree — allocated chunks the manifest forgot
  reclaim, garbage free entries clamp, and a doubly-referenced chunk
  fails the open as Corrupt instead of double-freeing.
- **Chunks** are write-through, independently framed; chunk index is AAD.
  Reads on tag failure raise an I/O error (`CrcError` at the Dokan seam),
  never plaintext.
- **Secrets** live in `PinnedBuffer`s (GC can't move them); the service
  copies caller buffers in, zeroes them out, and zeroes everything on
  `KeyGone`/dispose. Derived KEKs are scoped arrays, zeroed after each use.
- **Mount scope**: the Dokan letter is session-scoped (no MountManager
  registration) and the reported ACL names only the owning user — other
  sessions can't see the drive while it's mounted.
- **Unseal/mount are async** — the manifest decrypt (8 MiB) and the driver's
  mount call run on a pool thread with a generation counter dropping stale
  commits, so a key-pull mid-flight can't hold the pump or adopt a dead
  session's mount.
- **Rollback fence**: the manifest `seq` is monotonic; `config.VaultEpoch`
  — inside the keyfile's attestation MAC — is the trusted witness. An
  image that opens older than the attested epoch lands in `RolledBack`:
  unmounted, logged, and gated behind an explicit `vault accept-rollback`
  (the call moves the epoch *down* to the image — never silently). An
  image *ahead* of the epoch adopts forward and flags a re-attest.
- **TPM machine binding** (`vault tpm-bind`, format flag `TpmBound`): a
  32-byte *pepper* is generated and RSA-OAEP-SHA256-wrapped under a
  persisted user-scoped CNG key in the Microsoft Platform Crypto Provider
  (`tpmPepperBlob`). Bound KEKs fold the pepper into the HMAC input, so a
  copied image + cloned keyfile opens nowhere else. A non-strict bind also
  seals the pepper under the recovery phrase (`recPepperBlob`, AES-GCM
  under PBKDF2(phrase, "CKV-REC"‖headerSalt, `recIters`)) — the portable
  hatch when the TPM is cleared/replaced: `UnlockWithPhrase` recovers it,
  opens, and flags `NeedsRebind` until a live TPM re-wraps the blob.
  `--strict` skips the blob entirely (TPM clear ⇒ reformat). A bound image
  that can't unwrap reports `TpmLocked` — distinct from corruption and
  from the ratchet's `SealedDead`. Unbinding re-wraps the slots pepperless
  and deletes the CNG key best-effort.
- No ADS/hardlinks.

## Module inventory

The tree splits into a platform-neutral core (`src/CryptoKey.Core`,
`net9.0`, no Windows dependencies) and per-platform hosts
(`src/CryptoKey.Win` today). Hosts register a `PlatformServices` bundle via
`Platform.Init` at startup; Core statics resolve OS capabilities through it.

### `src/CryptoKey.Core` — platform-neutral

| File | Role |
|---|---|
| `CryptoKeyCli.cs` | Shared verb table — `enroll`, `status`, `guard`, `open`, `lock`, `pause`, `resume`, `quit`, `watchdog`; hosts keep their OS-specific roles |
| `Platform.cs` / `PlatformInterfaces.cs` / `PlatformImpls.cs` | The seam: `Platform.Services` ambient holder, one interface per OS capability (paths, protector, USB enum, key monitor, IPC ACLs, single-instance, stop-signal, lock policies, capture, system actions, config backup, keyfile attrs, app lifetime, lock surfaces, enroll extras, user alerts), shared null/file impls |
| `GuardService.cs` | State machine, unlock policy, backoff, ratchet orchestration, IPC dispatch, config reload |
| `KeyVerifier.cs` | v2 envelope wrap/unwrap, legacy keyfile compat, `RotateKeyfiles` |
| `Config.cs` | `KeyConfig`/`GuardSettings`, hashing, attestation, save + `.bak` mirror + third-copy fallback, `RotateSecret` |
| `RecoveryPhrase.cs` | Generated 20-char Crockford Base32 credential: `Generate`, `Normalize`, `IsValid` — the only user credential, stored hash-only |
| `AtomicFile.cs` | Durability primitive: tmp → device flush → rename (`FlushFileBuffers` / `F_FULLFSYNC` gated at runtime) — used by config, backup, keyfile, policy writes |
| `Enrollment.cs` / `EnrollmentFlow.cs` | Console adapter / the state machine behind it — drive selection, phrase confirm, keyfile + config write; the GUI wizard drives the same flow |
| `DesignTokens.cs` / `KeyArt.cs` / `PlatformCapabilities.cs` | One visual identity (ARGB tokens + shared key geometry) and a per-host capability record the UI gates features on |
| `ILockSurface.cs` | Lock abstraction: `Engage`/`Disengage`/`ReleaseInput`, tier marker (`IsOverlay`), `EngageError`, setters |
| `IpcServer.cs` / `IpcClient.cs` | Accept loop + dispatch marshal / one-shot CLI transport |
| `Watchdog.cs` | `Watchdog.Run` — heartbeat/respawn/OS-lock role + `Supervisor` — guard-side liveness probe, spawn, stop |
| `UsbDisk.cs` | One USB device: serial, model, mounted volume paths |
| `GuardState.cs` | `GuardState` + `StatusSnapshot` |
| `FlapPolicy.cs` | Desktop-flap classification + sliding-window storm counter — pure logic, unit-tested |
| `AlertService.cs` | Security-event push: POST + `Title` header to a user URL (ntfy.sh/webhook), 4 s, quiet after first failure |
| `Backoff.cs` | Phrase-freeze ladder (15s doubling → 300s cap) — extracted for the test suite |
| `Vault/VaultFormat.cs` | CKVAULT1 codecs — header page, KEK derivation, key-slot wrap/unwrap, chunk + manifest AES-GCM framing |
| `Vault/VaultVolume.cs` | The sealed device: image create/open, case-insensitive dir tree, freelist allocator, chunked R/W, dual-slot manifest with torn-write fallback, `PinnedBuffer` key hygiene |
| `Vault/VaultService.cs` | Lifecycle owner — consumes verified secrets from the guard, unseals/mounts on verify, force-dismounts on `KeyGone`, slides key slots on rotation |
| `UpdateChecker.cs` | GitHub-Releases channel: `releases/latest` check, sha256sums manifest parse, signature + tag-binding + hash verification, `.part`-atomic download, safe extract to staging |
| `ReleaseSigning.cs` | ECDSA-P256 release manifest signing — pinned public key, P1363 r‖s, gen-key/sign helpers for `sign-release` |

### `src/CryptoKey.Win` — Windows host (`cryptokey.exe`)

| File | Role |
|---|---|
| `WinPlatform.cs` | The `PlatformServices` bundle: `%APPDATA%` paths, DPAPI protector, WMI enumerator, mutex/event primitives, pipe SDDL, HKCU third copy, `LockWorkStation`, surface factory, MessageBox alerts |
| `Program.cs` | `Platform.Init` + argv dispatch — Windows-only roles (`install`, `--set-startup`, `--release-desktop`, `--lock-watchdog`, `--export-icon`), GUI/tray pump |
| `UsbMonitor.cs` | `IKeyMonitor` — hidden message window, `WM_DEVICECHANGE` + 1s poll fallback, error tolerance |
| `SecureLockSurface.cs` | Private desktop, STA lock thread, watchdog, switch-back discipline |
| `ClassicLockSurface.cs` | `LockScreen` + `InputLocker` adapter — pre-facade behavior |
| `LockScreen.cs` / `Ui/LockForm.cs` | Overlay manager (per-monitor) / the lock card form itself |
| `InputLocker.cs` | `WH_KEYBOARD_LL` + `WH_MOUSE_LL`, phrase buffer (char[], wiped), panic combo, hook-side cooldown |
| `NativeMethods.cs` | Win32 P/Invoke surface |
| `LockPolicies.cs` | While locked: HKCU `DisableTaskMgr`/`NoLogoff`/`NoClose` = 1 with exact prior-value backup/restore |
| `CaptureService.cs` | FlashCap one-shot webcam stills on tamper — fire-and-forget, single-flight, log-once failure; written DPAPI-sealed (`.cap`) |
| `Sounds.cs` | Synthesized PCM cues (lock thunk, unlock chime, storm blip) — generated WAVs, `SoundPlayer.Play` off-thread |
| `StartupManager.cs` | Run key vs scheduled task, content-validated `GetMode` |
| `ShortcutManager.cs` | `.lnk` writer (WScript.Shell) — Start Menu + Desktop targets, auto-created on enroll |
| `TrayIcons.cs` | Runtime badge renderer; `BuildIcoBytes` also produces the committed `app.ico` |
| `Vault/DokanVaultFileSystem.cs` | `IDokanOperations` adapter — translates driver callbacks to `VaultVolume`, maps results to `NtStatus` (tamper → `CrcError`) |
| `Vault/DokanMount.cs` | `IVaultMounter`/`IVaultMount` over DokanNet — mount thread, driver-presence probe, drive-letter selection, force-dismount |
| `EngineHost.cs` / `WinUi.cs` / `WinUiHost.cs` | The seam: engine thread + `GuardService` bootstrap, process composition, `IUiHost` shell integration |
| `Ui/LockForm.cs` / `Ui/KeyArtRenderer.cs` | The lock card (classic overlay + secure desktop host it) / GDI renderer for the shared `KeyArt` key visual |
| `Theme.cs` / `Ui/Glyphs.cs` / `TrayIcons.cs` | GDI palette/fonts/paint helpers (token-derived), Segoe glyph table, tray + app icon renderer |

### `src/CryptoKey.Ui` — shared front end (Avalonia 11)

| File | Role |
|---|---|
| `Design/` | `Palette`/`Motion` + `AppStyles.axaml` — the design system installed over the tokens |
| `Controls/` | `Kit` control factory (chips, rows, `HoldButton`, `SettingCombo`, toasts), `KeyVisual` (the animated key), `Icon` |
| `Shell/` | `CryptoKeyApp` + `UiRuntime` (loop + UI crash policy), `MainWindow` (sidebar + status rail), `UiShell` (tray + flyout + notifications), `TrayFlyout`, `NotificationCenter` |
| `Pages/` | Home, Key & Recovery, Vault, Protection, Alerts, Activity, General, About — pages read snapshots; all writes go through `GuardClient.UpdateSettings` |
| `Wizard/` | `OnboardingWindow` — first-run + re-enroll over `EnrollmentFlow` |
| `Services/` | `GuardClient` (the only engine door), `IUiHost` (per-OS shell integration), `Routes` |
| `Presenters/` | `HomePresenter`/`VaultPresenter`/activity parsing — pure snapshot→view-state, unit-tested |

### `src/CryptoKey.Mac` — macOS host (`cryptokey`, Avalonia 11)

| File | Role |
|---|---|
| `MacPlatform.cs` | The `PlatformServices` bundle: `~/Library/Application Support` paths, Keychain protector, DA enumerator, poll `MacKeyMonitor`, unix-socket IPC, `flock` single-instance + stand-down file, `FileConfigBackup`, `CGSession`/`pmset`/`osascript` actions, pump or Avalonia dispatcher, surface factory |
| `MacInterop.cs` | P/Invoke surface — CoreFoundation, CoreGraphics, Security, DiskArbitration, libc (`statfs`, `flock`), libobjc (`setLevel:`, activation policy) |
| `MacUsbEnumerator.cs` | `/Volumes` → `statfs` → `DADiskCreateFromBSDName` — removable + serial per mount, grouped per whole disk |
| `KeychainProtector.cs` | AES-GCM wrap key in the login Keychain (device-only accessible); entropy → AAD |
| `MacLockSurface.cs` | `CGEventTap` on its own run-loop thread + `CGDisplayCapture` + fixed char buffer; engage fails closed via `CGSession -suspend` |
| `Ui/` | `AvaloniaUiDispatcher`, `LockWindowCtl`/`LockWindow` (per-screen shielding cards in the shared design language — `KeyVisual`, token palette) |
| `MacUiHost.cs` | `IUiHost` — LaunchAgent autostart toggle, Dock icon while the dashboard is open, `open` shell-outs; the shared `UiShell` owns the menu-bar tray |
| `MacInstall.cs` | `install`/`uninstall` — payload copy to `~/Applications/CryptoKey`, LaunchAgent plist + `launchctl bootstrap`; `SetAutostart` is the quiet UI toggle |
| `Program.cs` | `Platform.Init` + argv dispatch — `CryptoKeyApp` tier by default (dashboard, tray, first-run wizard), `--headless` pump fallback, hidden `uitest` smoke |

`tests/CryptoKey.Tests` (xUnit, `net9.0`) covers the pure security
invariants — rotation chain (incl. `keepPrev` orphan-proofing),
envelope/attestation, tri-state match, `RotateKeyfiles` semantics, backoff
ladder, config-store round-trip, and the vault suite (header/kekslot
round-trips, two-generation seal window, chunk tamper → integrity error,
torn-manifest fallback, tree/alloc/capacity semantics, filename
confidentiality). The store is redirected into a temp dir
by `CRYPTOKEY_CONFIG_ROOT` and `Platform.Services` gets a null/temp
bundle — both set in a module initializer before any test code runs, so
the ambient can't be captured too early. The interactive layer
(`SecureLockSurface`/`SwitchDesktop`, pipe ACLs, WMI) stays manual — CI
agents are non-interactive.

`tests/CryptoKey.Ui.Tests` (xUnit + Avalonia.Headless) pins the front-end
safety invariants: page construction and refresh never persist config or
start timers, hold-to-confirm fires only on a real pointer hold, disabled
destructive buttons can't fire, and presenters render state honestly.
