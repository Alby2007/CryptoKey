using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace CryptoKey;

/// <summary>
/// State machine: key absent -> locked; key present -> verify serial +
/// keyfile hash -> unlocked. Locks immediately if the key is absent (or
/// fails verification) at startup, unless LockOnRemoval is off
/// (manual-lock-only mode). Paused suppresses auto-lock until expiry.
/// </summary>
internal sealed class GuardService : IDisposable
{
    private readonly KeyConfig _config;
    private readonly IKeyMonitor _monitor;
    private readonly IUiDispatcher _ui;
    private readonly bool _devMode;
    private readonly bool _forceClassic;
    private ILockSurface _surface;
    private readonly Supervisor _supervisor;
    private readonly VaultService _vault;
    private System.Threading.Timer? _watchdogTimer;

    private UsbDisk? _lastDisk;
    private string? _lastVerifyFailure;
    private DateTime? _pausedUntil;
    private int _failedAttempts;
    private StatusSnapshot? _lastSnapshot;
    private bool _verifiedEdge;
    private DateTime _lastRotateAttemptUtc = DateTime.MinValue;
    private string? _tamperNote;
    private bool _keyVerifiedNow;      // key factor currently armed (2FA gate)
    private bool _staleKeyPresent;     // a previous-generation file is on the drive
    private DateTime? _cooldownUntil;  // phrase-input freeze deadline
    private AttestState _lastAttest;   // dedup for the legacy-format log line

    public GuardService(KeyConfig config, bool devMode, bool forceClassic)
    {
        _config = config;
        _devMode = devMode;
        _forceClassic = forceClassic;
        var handle = Platform.Services.KeyMonitors.Create(config.DeviceSerial);
        _monitor = handle.Monitor;
        _ui = handle.Ui;
        _surface = CreateSurface(config, devMode, forceClassic);
        _supervisor = new Supervisor(msg => Log(msg));
        _vault = new VaultService(config, Platform.Services.VaultMounts, Log);
        _vault.StatusChanged += OnVaultStatusChanged;

        _monitor.PresenceChanged += OnPresenceChanged;
        _monitor.PresenceChecked += OnPresenceChecked;
        _monitor.ErrorLogged += Log;
        WireSurface(_surface);
    }

    /// <summary>
    /// "overlay" → overlay-class surface; anything else (including the
    /// "secure" default) → the platform's strong tier (private desktop /
    /// display capture). Secure mode auto-falls-back to overlay on engage
    /// failure, so it stays the safe default.
    /// </summary>
    private static ILockSurface CreateSurface(KeyConfig config, bool devMode, bool forceClassic)
        => Platform.Services.Surfaces.Create(
            securePreferred: !forceClassic
                && !config.Guard.LockMode.Equals("overlay", StringComparison.OrdinalIgnoreCase),
            devMode);

    private void WireSurface(ILockSurface s)
    {
        s.PassphraseSubmitted += OnPassphraseSubmitted;
        s.PanicRequested += OnPanic;
        s.SecurityEvent += OnSurfaceSecurityEvent;
    }

    /// <summary>
    /// Surface-reported security events — every kind logs; a "-storm"
    /// (repeated foreign-desktop switches while locked = scripted attack)
    /// also alerts and snaps.
    /// </summary>
    private void OnSurfaceSecurityEvent(string kind)
    {
        Log($"Security event: {kind}.");
        if (kind.EndsWith("-storm", StringComparison.Ordinal))
        {
            if (_config.Guard.Sounds)
                Platform.Services.Cues.Alarm();
            Snap("desktop-flap");
            Alert("Desktop flap storm", "repeated foreign-desktop switches while locked — workstation locked at OS level");
        }
    }

    private void OnPanic()
    {
        Log("Panic combo (Ctrl+Alt+Shift+F12) — exiting.");
        // Disengage BEFORE Exit — under the secure desktop, Exit while the
        // session is switched away can leave the user on an empty desktop.
        try { _surface.Disengage(); }
        catch (Exception) { }
        // Graceful exit — stand the watchdog down so it doesn't respawn us.
        _supervisor.Shutdown();
        Platform.Services.AppLifetime.Exit();
    }

    /// <summary>Mid-flight swap to the overlay-class surface (secure-engage failure).</summary>
    private void SwitchToClassic()
    {
        ILockSurface old = _surface;
        ILockSurface s = Platform.Services.Surfaces.Create(securePreferred: false, _devMode);
        WireSurface(s);
        s.SetAnimations(_config.Guard.Animations);
        _surface = s;
        try { old.Dispose(); }
        catch (Exception) { }
        Log("Falling back to overlay lock.");
    }

    /// <summary>
    /// The configured lock mode can change while the guard runs (Settings
    /// toggle writes config.json live) — rebuild the surface before engaging
    /// so the change applies to the NEXT lock.
    /// </summary>
    private void EnsureSurfaceMode()
    {
        bool wantClassic = _forceClassic
            || _config.Guard.LockMode.Equals("overlay", StringComparison.OrdinalIgnoreCase);
        if (wantClassic == _surface.IsOverlay)
            return;
        ILockSurface old = _surface;
        _surface = Platform.Services.Surfaces.Create(!wantClassic, _devMode);
        WireSurface(_surface);
        _surface.SetAnimations(_config.Guard.Animations);
        try { old.Dispose(); }
        catch (Exception) { }
        Log($"Lock mode → {(wantClassic ? "overlay" : "secure desktop")}.");
    }

    public GuardState State { get; private set; } = GuardState.Unlocked;

    /// <summary>Raised on the UI thread whenever the status snapshot changes.</summary>
    public event Action<StatusSnapshot>? StateChanged;

    /// <summary>Raised on every log line (timestamped) — feeds the dashboard activity list.</summary>
    public event Action<string>? ActivityLogged;

    /// <summary>
    /// User-facing heads-up (title, body) — the tray turns it into a balloon.
    /// Raised on the UI thread; currently only the idle-lock pre-warning uses it.
    /// </summary>
    public event Action<string, string>? Notification;

    private readonly List<string> _activity = new();

    /// <summary>Recent log lines, oldest first (for UI backfill).</summary>
    public IReadOnlyList<string> RecentActivity => _activity;

    /// <summary>Marshals work onto the pump the monitor owns (IPC dispatch goes through it).</summary>
    public IUiDispatcher UiDispatcher => _ui;

    /// <summary>The encrypted-vault lifecycle service — the Vault page and CLI drive it.</summary>
    public VaultService Vault => _vault;

    /// <summary>Vault state transitions fold into the snapshot stream + balloon on mount.</summary>
    private void OnVaultStatusChanged()
    {
        if (_vault.State == VaultState.Mounted && _config.Guard.BalloonTips)
            Notification?.Invoke("CryptoKey", $"Vault mounted at {_vault.MountPoint}");
        EmitSnapshot();
    }

    public void Start()
    {
        SeedActivityFromLog();
        // A stale backup means the last guard died while locked — restore
        // the user's policies before anything else. Moot under the OS lock
        // screen anyway; re-applied on the next lock.
        Platform.Services.LockPolicies.Restore(Log);
        _monitor.SetPollInterval(_config.Guard.PollIntervalMs);
        // Supervisor: bring the watchdog up now, then re-check every 5s —
        // a killed watchdog gets respawned; a disabled setting stands it down.
        SlowTick();
        _watchdogTimer = new System.Threading.Timer(
            _ => SlowTick(), null, 5000, 5000);
        _surface.SetAnimations(_config.Guard.Animations);
        Log($"Guard started (poll {_config.Guard.PollIntervalMs}ms, " +
            $"auto-lock {( _config.Guard.LockOnRemoval ? "on" : "off")}).");

        // Backup restore means the config *directory* was wiped — a
        // tamper-flavored event, louder than a plain .bak restore.
        if (ConfigStore.LastRestoreFromBackup)
        {
            Log("Config restored from the third-copy backup — the config directory had been wiped.");
            Alert("Config restore", "config restored from backup — config directory had been wiped");
        }
        UsbDisk? disk = null;
        try
        {
            disk = Platform.Services.Usb.FindDisk(_config.DeviceSerial);
        }
        catch (Exception ex)
        {
            Log($"USB enumeration failed at startup: {ex.Message}");
        }
        _lastDisk = disk;
        if (disk != null)
        {
            KeyfileCheck chk = KeyVerifier.Check(_config, disk);
            if (chk.Match != SecretMatch.None)
                Log($"Key verified at startup ({chk.Detail}) — unlocked.");
            else
                MaybeAutoLock("key absent or unverified at startup");
        }
        else
        {
            MaybeAutoLock("key absent or unverified at startup");
        }
        EmitSnapshot();
    }

    /// <summary>Shared ~5s cadence: watchdog supervision + idle lock.</summary>
    private void SlowTick()
    {
        WatchdogTick();
        IdleTick();
    }

    private void WatchdogTick()
    {
        try
        {
            if (_config.Guard.Watchdog)
                _supervisor.Ensure(Environment.ProcessId, _devMode, _forceClassic);
            else
                _supervisor.Stop(); // toggled off mid-run — stand it down
        }
        catch (Exception) { }
    }

    private IdleLockGate? _idleGate;
    private int _idleGateMins = -1;

    private void IdleTick()
    {
        int mins = _config.Guard.IdleLockMinutes;
        if (mins <= 0)
            return;
        try
        {
            if (_idleGate == null || _idleGateMins != mins)
            {
                _idleGate = new IdleLockGate(mins);
                _idleGateMins = mins;
            }
            uint idleMs = Platform.Services.SystemActions.IdleMilliseconds();
            // Lock on the UI thread — the timer callback is a pool thread.
            _ui.Post(new Action(() =>
            {
                // Paused/Locked suppress it; the gate stops re-locking on
                // the same idle streak after a key-present auto-unlock.
                if (State != GuardState.Unlocked)
                    return;
                switch (_idleGate.Check(idleMs))
                {
                    case IdleVerdict.Lock:
                        LockNow($"idle {mins} min");
                        break;
                    case IdleVerdict.Warn:
                        Log("Idle lock imminent — warning sent.");
                        Notification?.Invoke("CryptoKey",
                            "Idle lock in ~20 seconds — any input stays unlocked.");
                        break;
                }
            }));
        }
        catch (Exception) { }
    }

    /// <summary>Manual lock — always locks, clears any pause.</summary>
    public void RequestLock()
    {
        _pausedUntil = null;
        if (State == GuardState.Paused)
            SetState(GuardState.Unlocked);
        LockNow("manual lock");
    }

    /// <summary>Pause auto-lock while unlocked; removal won't lock until expiry.</summary>
    public bool Pause(int minutes, out string error)
    {
        if (minutes <= 0 || minutes > 24 * 60)
        {
            error = "minutes must be 1-1440";
            return false;
        }
        if (State == GuardState.Locked)
        {
            error = "can't pause while locked — unlock first";
            return false;
        }
        _pausedUntil = DateTime.Now.AddMinutes(minutes);
        SetState(GuardState.Paused);
        Log($"Paused {minutes} min (until {_pausedUntil:HH:mm:ss}).");
        error = "";
        return true;
    }

    /// <summary>End a pause early and re-arm immediately.</summary>
    public void Resume()
    {
        if (State != GuardState.Paused)
            return;
        _pausedUntil = null;
        SetState(GuardState.Unlocked);
        Log("Resumed.");
        if (_lastDisk == null || _lastVerifyFailure != null)
            MaybeAutoLock("key absent or unverified after resume");
    }

    /// <summary>
    /// Reload config.json after a re-enroll — the enroll process is separate,
    /// so without this the guard keeps verifying against the OLD serial and
    /// phrase hash until restart.
    /// </summary>
    public string ReloadConfig()
    {
        try
        {
            KeyConfig? fresh = ConfigStore.Load();
            if (fresh == null)
                return "err no config on disk";
            // Mutate in place, don't swap: dashboard/settings pages and the
            // phrase verifier all share _config — a swapped reference
            // would leave them reading (and saving over) a stale copy.
            _config.DeviceSerial = fresh.DeviceSerial;
            _config.SecretSalt = fresh.SecretSalt;
            _config.SecretHash = fresh.SecretHash;
            _config.PassphraseSalt = fresh.PassphraseSalt;
            _config.PassphraseHash = fresh.PassphraseHash;
            _config.PassphraseIterations = fresh.PassphraseIterations;
            _config.PrevSecretHash = fresh.PrevSecretHash;
            _config.RotationCount = fresh.RotationCount;
            _config.LastRotationUtc = fresh.LastRotationUtc;
            _config.Guard = fresh.Guard;
            _monitor.SetTargetSerial(fresh.DeviceSerial); // also triggers a re-check
            _monitor.SetPollInterval(fresh.Guard.PollIntervalMs);
            _failedAttempts = 0;
            _lastVerifyFailure = null;
            _verifiedEdge = false;
            _tamperNote = null;
            _keyVerifiedNow = false;
            _staleKeyPresent = false;
            _cooldownUntil = null;
            _surface.SetCooldown(null);
            _lastAttest = AttestState.Ok;
            _vault.ReloadConfig();
            Log($"Re-enrolled — now watching serial {fresh.DeviceSerial}.");
            return "ok re-enrolled";
        }
        catch (Exception ex)
        {
            Log($"Config reload failed: {ex.Message}");
            return $"err reload failed: {ex.Message}";
        }
    }

    /// <summary>Shut the guard down — refused while locked (quitting = unlocking).</summary>
    public bool RequestQuit()
    {
        if (State == GuardState.Locked)
            return false;
        Log("Quit requested — shutting down.");
        // Stand the watchdog down BEFORE the exit — quit is a clean death
        // and must not respawn. Defer the exit one pump turn so the IPC
        // reply gets written first.
        _supervisor.Shutdown();
        _ui.Post(() => Platform.Services.AppLifetime.Exit());
        return true;
    }

    public StatusSnapshot Snapshot()
        => new(State, _lastDisk != null, _lastDisk?.Model, _lastVerifyFailure,
            _pausedUntil, _tamperNote, _keyVerifiedNow, _supervisor.Alive,
            _vault.State is VaultState.Disabled or VaultState.NoImage
                ? null
                : new VaultStatus(_vault.State, _vault.MountPoint));

    /// <summary>Pipe command dispatch — must be called on the UI thread.</summary>
    public string DispatchCommand(string line)
    {
        string[] parts = line.Split(' ',
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length == 0)
            return "err empty command";

        switch (parts[0].ToLowerInvariant())
        {
            case "lock":
                RequestLock();
                return "ok locked";
            case "pause":
                int mins = parts.Length > 1 && int.TryParse(parts[1], out int m) ? m : 5;
                return Pause(mins, out string err)
                    ? $"ok paused until {_pausedUntil:HH:mm}"
                    : $"err {err}";
            case "resume":
                if (State != GuardState.Paused)
                    return "err not paused";
                Resume();
                return "ok resumed";
            case "quit":
                return RequestQuit()
                    ? "ok quitting"
                    : "err locked — insert the key or enter the recovery phrase first";
            case "reenrolled":
                return ReloadConfig();
            case "vault":
                return DispatchVault(parts);
            case "status":
                StatusSnapshot s = Snapshot();
                return $"ok state={s.State.ToString().ToLowerInvariant()} " +
                       $"key={(s.KeyPresent ? "present" : "absent")} " +
                       $"model=\"{s.Model ?? "-"}\" " +
                       $"verifyFail=\"{s.LastVerifyFailure ?? "-"}\" " +
                       $"pausedUntil={s.PausedUntil?.ToString("HH:mm:ss") ?? "-"} " +
                       $"tamper=\"{s.TamperNote ?? "-"}\" " +
                       $"keyVerified={_keyVerifiedNow} " +
                       $"policy={_config.Guard.UnlockPolicy} " +
                       $"watchdog={(s.WatchdogAlive ? "alive" : "down")} " +
                       $"vault={(s.Vault == null ? "off" :
                           s.Vault.State.ToString().ToLowerInvariant() +
                           (s.Vault.State == VaultState.Mounted ? $"@{s.Vault.MountPoint}" : ""))}";
            default:
                return $"err unknown command '{parts[0]}'";
        }
    }

    /// <summary>`cryptokey vault …` piped to a live guard — mount/unmount/create/status.</summary>
    private string DispatchVault(string[] parts)
    {
        if (parts.Length < 2)
            return "err usage: vault status|mount|unmount|create [mb]";
        switch (parts[1].ToLowerInvariant())
        {
            case "status":
                var usage = _vault.Usage;
                var hdr = VaultVolume.PeekHeader(_vault.ImagePath);
                string slots = hdr == null ? "-"
                    : $"{hdr.KeySlots[0].RotationGen}/{hdr.KeySlots[1].RotationGen}";
                return $"ok vault state={_vault.State.ToString().ToLowerInvariant()} " +
                       $"image=\"{_vault.ImagePath}\" " +
                       $"exists={_vault.ImageExists} " +
                       $"driver={(_vault.DriverPresent ? "present" : "missing")} " +
                       $"mount={(_vault.State == VaultState.Mounted ? _vault.MountPoint : "-")} " +
                       $"slots={slots} " +
                       $"used={(usage?.Used ?? 0)} total={(usage?.Total ?? 0)}";
            case "mount":
                return _vault.TryMount(out string mErr)
                    ? $"ok mounted at {_vault.MountPoint}"
                    : $"err {mErr}";
            case "unmount":
                // Unsealed may hide an in-flight auto-mount — TryUnmount fences it.
                if (_vault.State is not (VaultState.Mounted or VaultState.Unsealed))
                    return "err not mounted";
                return _vault.TryUnmount(out _) ? "ok unmounted" : "err unmount failed";
            case "create":
                int mb = parts.Length > 2 && int.TryParse(parts[2], out int m)
                    ? m : _config.Guard.VaultSizeMb;
                return _vault.TryCreate(mb, out string cErr)
                    ? "ok vault created" : $"err {cErr}";
            case "delete":
                return _vault.TryDeleteImage(out string dErr)
                    ? "ok vault deleted" : $"err {dErr}";
            default:
                return $"err unknown vault command '{parts[1]}'";
        }
    }

    /// <summary>Live-apply a new USB poll interval (ms) to the monitor and config.</summary>
    public void ApplyPollInterval(int ms)
    {
        _config.Guard.PollIntervalMs = ms;
        _monitor.SetPollInterval(ms);
    }

    /// <summary>Live-apply the reduce-motion setting to the lock surface.</summary>
    public void ApplyMotion(bool enabled) => _surface.SetAnimations(enabled);

    /// <summary>Fail-dead: free input (and the input desktop) — fatal-error path.</summary>
    public void ReleaseInput()
    {
        _surface.ReleaseInput();
        // Fail-dead frees the policies with the lock — restore is a no-op
        // when nothing was applied.
        Platform.Services.LockPolicies.Restore(Log);
    }

    // Removal locks instantly (when armed). Arrival deliberately does nothing
    // here — OnPresenceChecked re-verifies on every poll, which covers the lag
    // between the device node arriving and its volume mounting.
    private void OnPresenceChanged(bool present)
    {
        if (!present)
            MaybeAutoLock("key removed");
    }

    private void OnPresenceChecked(UsbDisk? disk)
    {
        _lastDisk = disk;
        CheckPauseExpiry();
        if (disk == null)
        {
            _verifiedEdge = false;
            _tamperNote = null;
            _keyVerifiedNow = false;
            _staleKeyPresent = false;
            _vault.KeyGone();
            // Under 2FA the screen may still say "Key verified — enter the
            // recovery phrase" from when the factor was armed; keep it honest.
            if (State == GuardState.Locked
                && _config.Guard.UnlockPolicy == UnlockPolicy.KeyAndPassphrase)
            {
                _surface.SetStatus("Key removed — insert it, then enter the recovery phrase.");
            }
            EmitSnapshot();
            return;
        }

        KeyfileCheck check = KeyVerifier.Check(_config, disk);
        if (check.Match != SecretMatch.None)
        {
            bool strict = _config.Guard.StrictTamper;
            bool stale = check.Match == SecretMatch.Previous;
            _staleKeyPresent = stale;
            // Strict tamper: a stale secret never counts as the key factor.
            _keyVerifiedNow = !stale || !strict;
            _lastVerifyFailure = null;
            bool edgeFlip = !_verifiedEdge;
            // The vault consumes the verified secret for its key slots —
            // a stale secret counts only when it counts for the lock, and
            // an attestation mismatch seals the vault even though the
            // secret itself checked out (config tamper is vault tamper).
            if (_keyVerifiedNow && check.Attest != AttestState.Mismatch)
                _vault.KeyVerified(check.Secret!,
                    (uint)(stale ? Math.Max(1, _config.RotationCount - 1)
                                 : _config.RotationCount));
            else
            {
                if (check.Secret != null)
                    CryptographicOperations.ZeroMemory(check.Secret);
                _vault.KeyGone();
            }
            _verifiedEdge = true;

            // Tamper reporting — a replayed old secret is what a clone looks
            // like; attestation failures flag config.json tampering or a
            // forged keyfile. The badge is for real alerts only — a legacy
            // (pre-v2) file is benign and self-upgrades on rotation, so it
            // gets a dedup'd log line instead of a clone alarm.
            string? note = stale ? "possible clone — stale keyfile replayed"
                : check.Attest == AttestState.Mismatch
                    ? "config attestation failed — config.json tampered"
                : null;
            if (check.Attest == AttestState.Missing && _lastAttest != AttestState.Missing)
                Log("Keyfile is pre-attestation (legacy) — upgrades to v2 on this rotation.");
            _lastAttest = check.Attest;
            if (note != _tamperNote)
            {
                _tamperNote = note;
                if (note != null)
                {
                    string msg = stale
                        ? "Keyfile presented a previous-generation secret — " +
                          "possible clone or interrupted rotation."
                        : "Keyfile attestation mismatch — config.json " +
                          "tampered or the keyfile was forged.";
                    Log(msg);
                    Snap("tamper");
                    Alert("Tamper", msg);
                }
            }

            if (State == GuardState.Locked)
            {
                UnlockPolicy policy = _config.Guard.UnlockPolicy;
                bool autoUnlock = policy != UnlockPolicy.KeyAndPassphrase
                    && (!stale || !strict);
                if (autoUnlock)
                {
                    UnlockNow();
                }
                else
                {
                    _surface.SetStatus(policy switch
                    {
                        UnlockPolicy.KeyAndPassphrase when _keyVerifiedNow
                            => "Key verified — enter the recovery phrase.",
                        UnlockPolicy.KeyAndPassphrase
                            => "Stale keyfile — recovery phrase required.",
                        UnlockPolicy.KeyOnly
                            => "Stale keyfile — attempting repair (re-enroll if it persists).",
                        _ => "Stale keyfile — type the recovery phrase.",
                    });
                }
            }

            // Burn the secret once per key session (edge), and whenever a
            // stale file shows up (heals interrupted rotations), throttled.
            // Under 2FA/strict policies the lock stays engaged here — the
            // write goes to a worker so a stalled USB write can't hold the
            // hook pump open.
            if ((edgeFlip || stale)
                && DateTime.UtcNow - _lastRotateAttemptUtc > TimeSpan.FromSeconds(5))
            {
                _lastRotateAttemptUtc = DateTime.UtcNow;
                // Pin prev when the drive IS the previous generation — a failed
                // write must leave it still-verifiable, not two gens behind.
                TryRotate(disk, keepPrev: stale, backgroundWrite: true);
            }
        }
        else
        {
            _verifiedEdge = false;
            _tamperNote = null;
            _keyVerifiedNow = false;
            _staleKeyPresent = false;
            _vault.KeyGone(); // present but unverified — the vault seals too
            bool changed = check.Detail != _lastVerifyFailure;
            _lastVerifyFailure = check.Detail;
            if (State != GuardState.Locked)
            {
                if (changed)
                    Log($"Key stopped verifying ({check.Detail}).");
                MaybeAutoLock("key unverified");
            }
            else if (changed)
            {
                Log($"Key detected but verification failed: {check.Detail}");
                _surface.SetStatus($"CryptoKey detected — {check.Detail}. Or type the recovery phrase.");
            }
        }
        EmitSnapshot();
    }

    /// <summary>
    /// Forced rotation outside the edge/throttle gate — the phrase-change
    /// path uses it to re-attest (the MAC covers the phrase hash, so a
    /// change invalidates every existing keyfile). False when the key is
    /// absent or no letter accepted the write.
    /// </summary>
    public bool RotateNow()
    {
        if (_lastDisk == null)
            return false;
        _lastRotateAttemptUtc = DateTime.UtcNow;
        // Only reachable unlocked (the UI is unreachable while locked), so a
        // synchronous write is safe — and the caller needs the real result.
        return TryRotate(_lastDisk, keepPrev: false, backgroundWrite: false);
    }

    /// <summary>
    /// Deliberate re-arm: rotate and rewrite the keyfile when the attached
    /// enrolled drive is failing to verify (wiped/corrupt file). Explicitly
    /// NOT an auto-heal — auto-writing on a failed check would hand a
    /// working keyfile to any drive spoofing the serial. Gated on the
    /// unlocked session, which is the same trust bar as enrollment.
    /// </summary>
    public bool RepairKeyfile()
    {
        if (State == GuardState.Locked)
            return false;
        if (_lastDisk == null)
        {
            Log("Keyfile repair: enrolled drive not attached.");
            return false;
        }
        if (KeyVerifier.Check(_config, _lastDisk).Match == SecretMatch.Current)
        {
            Log("Keyfile repair: key already verifies — nothing to repair.");
            return true;
        }
        Log("Repairing keyfile — writing a fresh envelope to the attached drive.");
        _lastRotateAttemptUtc = DateTime.UtcNow;
        bool ok = TryRotate(_lastDisk, keepPrev: false, backgroundWrite: false);
        Log(ok ? "Keyfile repaired — drive re-armed."
               : "Keyfile repair failed — see rotation errors above.");
        return ok;
    }

    /// <summary>
    /// Single-use ratchet: burn the secret the drive presented. Config first,
    /// then the drive — a crash anywhere leaves the drive on the previous
    /// generation, which still verifies as stale and heals on the next pass.
    /// The state mutation, config save, and envelope wrap stay on the UI
    /// thread (fast, keeps _config coherent); with backgroundWrite the drive
    /// I/O moves to a worker so a stalled USB write can never delay the hook
    /// pump while locked.
    /// </summary>
    private bool TryRotate(UsbDisk disk, bool keepPrev, bool backgroundWrite)
    {
        byte[] next = RandomNumberGenerator.GetBytes(64);

        string oldSecret = _config.SecretHash, oldPrev = _config.PrevSecretHash;
        int oldCount = _config.RotationCount;
        DateTime? oldRot = _config.LastRotationUtc;
        ConfigStore.RotateSecret(_config, next, keepPrev);
        try
        {
            ConfigStore.Save(_config);
        }
        catch (Exception ex)
        {
            // Roll the mutation back — memory, file, and drive must agree.
            _config.SecretHash = oldSecret;
            _config.PrevSecretHash = oldPrev;
            _config.RotationCount = oldCount;
            _config.LastRotationUtc = oldRot;
            Log($"Rotation aborted — config save failed ({ex.Message}).");
            return false;
        }

        byte[] envelope;
        try
        {
            envelope = KeyVerifier.WrapKeyfile(next, _config);
        }
        catch (Exception ex)
        {
            Log($"Rotation failed — envelope error ({ex.Message}).");
            return false;
        }
        int gen = _config.RotationCount;

        if (backgroundWrite)
        {
            Task.Run(() =>
            {
                List<string> lines;
                try
                {
                    lines = RotationLog(KeyVerifier.RotateKeyfiles(disk, envelope), gen);
                }
                catch (Exception ex)
                {
                    lines = new List<string>
                        { $"Rotation write failed ({ex.Message}) — drive is stale, heals on retry." };
                }
                try { _ui.Post(new Action(() => lines.ForEach(Log))); }
                catch (Exception) { /* monitor dead — feed already closed */ }
            });
            return true; // config committed — the drive write lands on a worker
        }

        try
        {
            var results = KeyVerifier.RotateKeyfiles(disk, envelope);
            RotationLog(results, gen).ForEach(Log);
            return results.Count > 0 && results.Any(r => r.Error == null);
        }
        catch (Exception ex)
        {
            Log($"Rotation write failed ({ex.Message}) — drive is stale, heals on retry.");
            return false;
        }
    }

    private static List<string> RotationLog(
        List<(string Letter, string? Error)> results, int gen)
    {
        if (results.Count == 0)
            return new List<string> { $"Config rotated to generation {gen} but the drive " +
                "has no mounted volume — the drive secret is stale until it reappears." };
        if (results.All(r => r.Error == null))
            return new List<string> { $"Keyfile rotated to generation {gen}." };
        return new List<string> { $"Rotated to generation {gen} with issues: " +
            string.Join("; ", results.Select(r
                => r.Error == null ? $"{r.Letter} ok" : $"{r.Letter} {r.Error}")) + "." };
    }

    private void CheckPauseExpiry()
    {
        if (_pausedUntil == null || DateTime.Now < _pausedUntil.Value)
            return;
        _pausedUntil = null;
        if (State == GuardState.Paused)
        {
            SetState(GuardState.Unlocked);
            Log("Pause expired.");
        }
        if (_lastDisk == null)
            MaybeAutoLock("pause expired, key absent");
    }

    private void OnPassphraseSubmitted(char[] attempt)
    {
        // This runs inside the low-level keyboard hook — return instantly or
        // the hook times out and keystrokes leak through unswallowed. PBKDF2
        // runs off-thread and the result is marshaled back to the UI. The
        // attempt buffer is wiped in every path — it's the only copy.

        // Belt-and-braces: the hook drops input during cooldown, but an Enter
        // queued just before the freeze could still land here.
        if (_cooldownUntil is DateTime until && DateTime.Now < until)
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(attempt.AsSpan()));
            return;
        }

        UnlockPolicy policy = _config.Guard.UnlockPolicy;
        // Is the input even phrase-shaped? A failed verify of a valid
        // XXXXX-XXXXX-XXXXX-XXXXX is "wrong phrase"; anything else is most
        // likely a legacy free-form passphrase — say so rather than just
        // "incorrect" (they were retired when phrases replaced them).
        Span<char> shape = stackalloc char[64];
        bool notPhraseShaped;
        try
        {
            int n = RecoveryPhrase.Normalize(attempt.AsSpan(), shape);
            notPhraseShaped = !RecoveryPhrase.IsValid(shape[..Math.Min(n, shape.Length)]);
        }
        finally
        {
            shape.Clear();
        }

        Task.Run(() =>
        {
            bool ok;
            try
            {
                ok = ConfigStore.VerifyPassphrase(_config, attempt);
            }
            catch (Exception)
            {
                ok = false;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(attempt.AsSpan()));
            }

            try
            {
                _ui.Post(new Action(() => OnPassphraseResult(ok, policy, notPhraseShaped)));
            }
            catch (Exception)
            {
                // UI thread is gone — the process is exiting anyway.
            }
        });
    }

    private void OnPassphraseResult(bool ok, UnlockPolicy policy, bool notPhraseShaped)
    {
        if (!ok)
        {
            _failedAttempts++;
            _surface.SetFailedAttempts(_failedAttempts);
            Snap("badpass");
            // Exponential cooldown: fails 1-2 free, then 15s/30s/60s/120s/…
            // capped at 300s. Enforced in the hook so mashing can't pile up.
            int secs = Backoff.Seconds(_failedAttempts);
            if (secs > 0)
            {
                var until = DateTime.Now.AddSeconds(secs);
                _cooldownUntil = until;
                _surface.SetCooldown(until);
                _surface.SetStatus($"Too many attempts — input frozen for {secs}s.");
                Log($"Recovery-phrase failed attempt #{_failedAttempts} — input frozen {secs}s.");
            }
            else if (notPhraseShaped)
            {
                _surface.SetStatus("That's not a recovery phrase — credentials are " +
                    "generated XXXXX-XXXXX-XXXXX-XXXXX phrases now. Old passphrases " +
                    "were retired; unlock with the key and regenerate on the Security tab.");
            }
            else
            {
                _surface.SetStatus("Incorrect recovery phrase — try again.");
            }
            return;
        }

        // Correct phrase — now the policy gate decides.
        _failedAttempts = 0;
        _cooldownUntil = null;
        _surface.SetCooldown(null);
        _surface.SetFailedAttempts(0);

        if (policy == UnlockPolicy.KeyOnly)
        {
            _surface.SetStatus("The recovery phrase is disabled — insert the key.");
            return;
        }
        if (policy == UnlockPolicy.KeyAndPassphrase && !_keyVerifiedNow)
        {
            // Break-glass: under strict tamper a stale key never counts as
            // the factor, but the recovery phrase remains an explicit failsafe —
            // the unlock happens WITH the tamper alarm already raised.
            if (_config.Guard.StrictTamper && _staleKeyPresent)
            {
                Log("Break-glass unlock — recovery phrase accepted over a stale keyfile.");
                Snap("breakglass");
                Alert("Break-glass", "recovery phrase accepted over a stale keyfile");
                UnlockNow();
            }
            else
            {
                _surface.SetStatus("Recovery phrase correct — insert your key first.");
            }
            return;
        }
        Log("Unlocked via recovery phrase — re-locks on next key removal.");
        UnlockNow();
    }

    private void MaybeAutoLock(string reason)
    {
        if (State == GuardState.Locked || State == GuardState.Paused)
            return;
        if (!_config.Guard.LockOnRemoval)
            return;
        LockNow(reason);
    }

    private void LockNow(string reason)
    {
        if (State == GuardState.Locked)
            return;
        _pausedUntil = null;
        _failedAttempts = 0;
        _keyVerifiedNow = false; // fresh lock session — poll re-arms if the key verifies
        _vault.KeyGone(); // the vault seals with the session — before the surface drops
        Log($"LOCKED — {reason}.");
        SetState(GuardState.Locked);
        Alert("Locked", $"locked — {reason}");
        if (_config.Guard.Sounds)
            Platform.Services.Cues.Lock();
        // Policies apply even if both surfaces fail — the user is still
        // locked (degraded, screen-only) and shouldn't get Task Manager back.
        if (_config.Guard.LockPolicies)
            Platform.Services.LockPolicies.Apply(Log);
        // Secure first; any engage failure — returned or thrown — falls back
        // to the classic overlay. A throw propagating out of here would kill
        // the guard via the poll callback while State is already Locked.
        EnsureSurfaceMode();
        bool engaged;
        try { engaged = _surface.Engage(); }
        catch (Exception ex)
        {
            Log($"Lock surface engage threw ({ex.Message}).");
            engaged = false;
        }
        if (!engaged && !_surface.IsOverlay)
        {
            Log($"Secure lock failed to engage ({_surface.EngageError ?? "unknown"}).");
            SwitchToClassic();
            try { engaged = _surface.Engage(); }
            catch (Exception ex)
            {
                Log($"Overlay engage also threw ({ex.Message}).");
                engaged = false;
            }
        }
        if (!engaged)
        {
            Log("WARNING: input hooks failed — INPUT IS NOT BLOCKED.");
            _surface.SetStatus("WARNING: input hooks failed — screen only. Ctrl+Alt+Del to recover.");
        }
        else
        {
            _surface.ResetStatus();
        }
    }

    private void UnlockNow()
    {
        if (State != GuardState.Locked)
            return;
        _lastVerifyFailure = null;
        // Cooldown dies with the lock session — in-memory only per design.
        _cooldownUntil = null;
        _surface.SetCooldown(null);
        // Disengage returns input (and the input desktop) before teardown.
        // If the session couldn't be switched back, the surface stays alive
        // and functional — keep State locked so the phrase path still
        // works and the next unlock retries the switch.
        if (!_surface.Disengage())
        {
            Log("Unlock deferred — could not switch back to the input desktop.");
            _surface.SetStatus("Couldn't return to your desktop — try again.");
            return;
        }
        Platform.Services.LockPolicies.Restore(Log);
        Log("Unlocked.");
        SetState(GuardState.Unlocked);
        Alert("Unlocked", "session unlocked");
        if (_config.Guard.Sounds)
            Platform.Services.Cues.Unlock();
    }

    private void SetState(GuardState state)
    {
        if (State == state)
            return;
        State = state;
        EmitSnapshot();
    }

    private void EmitSnapshot()
    {
        StatusSnapshot snap = Snapshot();
        if (snap == _lastSnapshot)
            return;
        _lastSnapshot = snap;
        StateChanged?.Invoke(snap);
    }

    private static string LogPath => Path.Combine(ConfigStore.ConfigDir, "guard.log");
    private static string OldLogPath => Path.Combine(ConfigStore.ConfigDir, "guard.log.1");

    /// <summary>Append a line to the feed/console/guard.log — also used by IPC startup.</summary>
    /// <summary>Webcam snap if enabled — fire-and-forget, failures self-log once.</summary>
    private void Snap(string reason)
    {
        if (_config.Guard.WebcamOnTamper)
            Platform.Services.Capture.Snap(reason, Log);
    }

    /// <summary>Push an event to the configured alert endpoint; "" URL = off.</summary>
    private void Alert(string title, string body)
        => AlertService.Send(_config.Guard.AlertUrl, title, body, Log);

    public void Log(string message)
    {
        string line = $"[{DateTime.Now:HH:mm:ss}] {message}";
        Console.WriteLine(line);
        _activity.Add(line);
        if (_activity.Count > 200)
            _activity.RemoveAt(0);
        try
        {
            Directory.CreateDirectory(ConfigStore.ConfigDir);
            var fi = new FileInfo(LogPath);
            if (fi.Exists && fi.Length > 256 * 1024)
                File.Move(LogPath, OldLogPath, overwrite: true);
            File.AppendAllText(LogPath, $"[{DateTime.Now:MM-dd HH:mm:ss}] {message}\r\n");
        }
        catch (Exception) { /* logging must never take down the guard */ }
        ActivityLogged?.Invoke(line);
    }

    /// <summary>Backfills the activity feed with the tail of the previous log.</summary>
    private void SeedActivityFromLog()
    {
        try
        {
            if (!File.Exists(LogPath))
                return;
            string[] lines = File.ReadAllLines(LogPath);
            foreach (string line in lines.TakeLast(60))
                if (!string.IsNullOrWhiteSpace(line))
                    _activity.Add(line);
        }
        catch (Exception) { }
    }

    public void Dispose()
    {
        // Every graceful exit funnels through Dispose — standing the
        // watchdog down here catches paths beyond quit/panic (window close,
        // takeover handoff). Ungraceful deaths never reach this — by design.
        _supervisor.Shutdown();
        _watchdogTimer?.Dispose();
        _vault.Dispose(); // dismounts + zeroes keys — before surface teardown
        Platform.Services.LockPolicies.Restore(Log);
        _surface.Dispose();
        _monitor.Dispose();
    }
}

internal enum IdleVerdict { None, Warn, Lock }

/// <summary>
/// One warn + one lock per idle streak. Fires Warn the first time the idle
/// counter crosses (threshold − 20s), Lock at the threshold, then stays
/// suppressed until input brings the counter back under the warn edge —
/// without this, idle-locking a machine whose key is still inserted flaps
/// forever: lock → key auto-unlock → re-lock, plus an alert pair per cycle.
/// </summary>
internal sealed class IdleLockGate
{
    private const int WarnLeadMs = 20_000;
    private readonly uint _thresholdMs;
    private readonly uint _warnMs;
    private bool _warned;
    private bool _suppressed;

    internal IdleLockGate(int minutes)
    {
        _thresholdMs = (uint)minutes * 60_000;
        // Warn edge sits ~20s before the lock edge; sub-20s thresholds
        // clamp to 0 so a warn never outruns the lock itself.
        _warnMs = _thresholdMs > WarnLeadMs ? _thresholdMs - WarnLeadMs : 0;
    }

    internal IdleVerdict Check(uint idleMs)
    {
        if (idleMs < _warnMs)
        {
            // Input returned — both edges re-arm for the next streak.
            _warned = _suppressed = false;
            return IdleVerdict.None;
        }
        if (idleMs >= _thresholdMs)
        {
            if (_suppressed)
                return IdleVerdict.None;
            _suppressed = true;
            return IdleVerdict.Lock;
        }
        if (_warned)
            return IdleVerdict.None;
        _warned = true;
        return IdleVerdict.Warn;
    }

    /// <summary>True once when idle crosses the threshold; re-arms when input returns.</summary>
    internal bool ShouldLock(uint idleMs) => Check(idleMs) == IdleVerdict.Lock;
}
