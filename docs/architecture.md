# Architecture

## Process roles — one exe, several hats

`CryptoKey.exe` dispatches on `argv` before anything else happens. All roles
share the same binary and config (the diagram shows the Windows host —
[macos.md](macos.md) has the Mac equivalents):

```mermaid
flowchart TD
    A[cryptokey ...] --> B{argv}
    B -->|"bare / open"| GUI["Dashboard app<br/>guard + AppShell + pages"]
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
- **No service process.** The daemon is a WinForms app with its console
  hidden; autostart launches `cryptokey.exe guard` via the Run key or a
  scheduled task.

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
        TRAY["TrayApp<br/>NotifyIcon"]
        UI["AppShell + pages<br/>dashboard"]
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
device it drives. The dashboard, tray, settings pages, and IPC commands all
consume the same `_config` instance and the same event surface
(`StateChanged` snapshots + `LogWritten` activity lines).

## Threading model

| Thread | Owns | Rules |
|---|---|---|
| **UI thread** | `GuardService`, monitor callbacks (marshaled via `BeginInvoke`), config mutation, rotation bookkeeping | Must never block on USB I/O while hooks may be installed — rotation writes go to a worker |
| **WMI worker** (`UsbMonitor`) | `Win32_DiskDrive` enumeration | Polls off-pump so a slow WMI query can't stall hooks; results marshal to the UI thread |
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
| `captures\*.jpg` | `%APPDATA%\CryptoKey\captures\` | Webcam tamper stills (opt-in) — newest 50 kept |
| Registry / Task Scheduler | `HKCU\...\Run\CryptoKey`, task `CryptoKey` | Startup modes — validated by content, not just presence |

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
| `Enrollment.cs` | Drive selection, phrase display/confirm, keyfile + config write, `reenrolled` ping |
| `ILockSurface.cs` | Lock abstraction: `Engage`/`Disengage`/`ReleaseInput`, tier marker (`IsOverlay`), `EngageError`, setters |
| `IpcServer.cs` / `IpcClient.cs` | Accept loop + dispatch marshal / one-shot CLI transport |
| `Watchdog.cs` | `Watchdog.Run` — heartbeat/respawn/OS-lock role + `Supervisor` — guard-side liveness probe, spawn, stop |
| `UsbDisk.cs` | One USB device: serial, model, mounted volume paths |
| `GuardState.cs` | `GuardState` + `StatusSnapshot` |
| `FlapPolicy.cs` | Desktop-flap classification + sliding-window storm counter — pure logic, unit-tested |
| `AlertService.cs` | Security-event push: POST + `Title` header to a user URL (ntfy.sh/webhook), 4 s, quiet after first failure |
| `Backoff.cs` | Phrase-freeze ladder (15s doubling → 300s cap) — extracted for the test suite |

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
| `CaptureService.cs` | FlashCap one-shot webcam stills on tamper — fire-and-forget, single-flight, log-once failure |
| `StartupManager.cs` | Run key vs scheduled task, content-validated `GetMode` |
| `ShortcutManager.cs` | `.lnk` writer (WScript.Shell) — Start Menu + Desktop targets, auto-created on enroll |
| `TrayIcons.cs` | Runtime badge renderer; `BuildIcoBytes` also produces the committed `app.ico` |
| `TrayApp.cs`, `Ui/` | NotifyIcon, AppShell, dashboard/settings/security/log pages, theming |

### `src/CryptoKey.Mac` — macOS host (`cryptokey`, Avalonia 11)

| File | Role |
|---|---|
| `MacPlatform.cs` | The `PlatformServices` bundle: `~/Library/Application Support` paths, Keychain protector, DA enumerator, poll `MacKeyMonitor`, unix-socket IPC, `flock` single-instance + stand-down file, `FileConfigBackup`, `CGSession`/`pmset`/`osascript` actions, pump or Avalonia dispatcher, surface factory |
| `MacInterop.cs` | P/Invoke surface — CoreFoundation, CoreGraphics, Security, DiskArbitration, libc (`statfs`, `flock`), libobjc (`setLevel:`, activation policy) |
| `MacUsbEnumerator.cs` | `/Volumes` → `statfs` → `DADiskCreateFromBSDName` — removable + serial per mount, grouped per whole disk |
| `KeychainProtector.cs` | AES-GCM wrap key in the login Keychain (device-only accessible); entropy → AAD |
| `MacLockSurface.cs` | `CGEventTap` on its own run-loop thread + `CGDisplayCapture` + fixed char buffer; engage fails closed via `CGSession -suspend` |
| `Ui/` | `MacApp` + `AvaloniaUiDispatcher`, `LockWindowCtl`/`LockWindow` (per-screen shielding cards), `MacTray` (menu-bar verbs → `DispatchCommand`) |
| `MacInstall.cs` | `install`/`uninstall` — payload copy to `~/Applications/CryptoKey`, LaunchAgent plist + `launchctl bootstrap` |
| `Program.cs` | `Platform.Init` + argv dispatch — UI tier by default, `--headless` pump fallback, hidden `uitest` smoke |

`tests/CryptoKey.Tests` (xUnit, `net9.0`) covers the pure security
invariants — rotation chain (incl. `keepPrev` orphan-proofing),
envelope/attestation, tri-state match, `RotateKeyfiles` semantics, backoff
ladder, config-store round-trip. The store is redirected into a temp dir
by `CRYPTOKEY_CONFIG_ROOT` and `Platform.Services` gets a null/temp
bundle — both set in a module initializer before any test code runs, so
the ambient can't be captured too early. The interactive layer
(`SecureLockSurface`/`SwitchDesktop`, pipe ACLs, WMI) stays manual — CI
agents are non-interactive.
