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
    private readonly UsbMonitor _monitor;
    private readonly bool _devMode;
    private readonly bool _forceClassic;
    private ILockSurface _surface;

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
    private DateTime? _cooldownUntil;  // passphrase-input freeze deadline
    private AttestState _lastAttest;   // dedup for the legacy-format log line

    public GuardService(KeyConfig config, bool devMode, bool forceClassic)
    {
        _config = config;
        _devMode = devMode;
        _forceClassic = forceClassic;
        _monitor = new UsbMonitor(config.DeviceSerial);
        _surface = CreateSurface(config, devMode, forceClassic);

        _monitor.PresenceChanged += OnPresenceChanged;
        _monitor.PresenceChecked += OnPresenceChecked;
        _monitor.ErrorLogged += Log;
        WireSurface(_surface);
    }

    /// <summary>
    /// "overlay" → classic per-monitor overlay; anything else (including the
    /// "secure" default) → private-desktop lock. Secure mode auto-falls-back
    /// to overlay on engage failure, so it stays the safe default.
    /// </summary>
    private static ILockSurface CreateSurface(KeyConfig config, bool devMode, bool forceClassic)
        => !forceClassic && !config.Guard.LockMode.Equals("overlay", StringComparison.OrdinalIgnoreCase)
            ? (ILockSurface)new SecureLockSurface(devMode)
            : new ClassicLockSurface(devMode);

    private void WireSurface(ILockSurface s)
    {
        s.PassphraseSubmitted += OnPassphraseSubmitted;
        s.PanicRequested += OnPanic;
    }

    private void OnPanic()
    {
        Log("Panic combo (Ctrl+Alt+Shift+F12) — exiting.");
        // Disengage BEFORE Exit — under the secure desktop, Exit while the
        // session is switched away can leave the user on an empty desktop.
        try { _surface.Disengage(); }
        catch (Exception) { }
        Application.Exit();
    }

    /// <summary>Mid-flight swap to the classic overlay (secure-engage failure).</summary>
    private void SwitchToClassic()
    {
        ILockSurface old = _surface;
        var s = new ClassicLockSurface(_devMode);
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
        if (wantClassic == (_surface is ClassicLockSurface))
            return;
        ILockSurface old = _surface;
        _surface = wantClassic
            ? new ClassicLockSurface(_devMode)
            : new SecureLockSurface(_devMode);
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

    private readonly List<string> _activity = new();

    /// <summary>Recent log lines, oldest first (for UI backfill).</summary>
    public IReadOnlyList<string> RecentActivity => _activity;

    /// <summary>Message-pump owner used to marshal pipe commands onto the UI thread.</summary>
    public Control InvokeTarget => _monitor;

    public void Start()
    {
        SeedActivityFromLog();
        _monitor.SetPollInterval(_config.Guard.PollIntervalMs);
        _surface.SetAnimations(_config.Guard.Animations);
        Log($"Guard started (poll {_config.Guard.PollIntervalMs}ms, " +
            $"auto-lock {( _config.Guard.LockOnRemoval ? "on" : "off")}).");
        UsbDisk? disk = null;
        try
        {
            disk = UsbMonitor.FindDisk(_config.DeviceSerial);
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
    /// passphrase hash until restart.
    /// </summary>
    public string ReloadConfig()
    {
        try
        {
            KeyConfig? fresh = ConfigStore.Load();
            if (fresh == null)
                return "err no config on disk";
            // Mutate in place, don't swap: dashboard/settings pages and the
            // passphrase verifier all share _config — a swapped reference
            // would leave them reading (and saving over) a stale copy.
            _config.DeviceSerial = fresh.DeviceSerial;
            _config.SecretSalt = fresh.SecretSalt;
            _config.SecretHash = fresh.SecretHash;
            _config.PassphraseSalt = fresh.PassphraseSalt;
            _config.PassphraseHash = fresh.PassphraseHash;
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
        // Defer the exit one pump turn so the IPC reply gets written first.
        _monitor.BeginInvoke(() => Application.Exit());
        return true;
    }

    public StatusSnapshot Snapshot()
        => new(State, _lastDisk != null, _lastDisk?.Model, _lastVerifyFailure,
            _pausedUntil, _tamperNote, _keyVerifiedNow);

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
                    : "err locked — insert the key or enter the passphrase first";
            case "reenrolled":
                return ReloadConfig();
            case "status":
                StatusSnapshot s = Snapshot();
                return $"ok state={s.State.ToString().ToLowerInvariant()} " +
                       $"key={(s.KeyPresent ? "present" : "absent")} " +
                       $"model=\"{s.Model ?? "-"}\" " +
                       $"verifyFail=\"{s.LastVerifyFailure ?? "-"}\" " +
                       $"pausedUntil={s.PausedUntil?.ToString("HH:mm:ss") ?? "-"} " +
                       $"tamper=\"{s.TamperNote ?? "-"}\" " +
                       $"keyVerified={_keyVerifiedNow} " +
                       $"policy={_config.Guard.UnlockPolicy}";
            default:
                return $"err unknown command '{parts[0]}'";
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
    public void ReleaseInput() => _surface.ReleaseInput();

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
            // Under 2FA the screen may still say "Key verified — enter the
            // passphrase" from when the factor was armed; keep it honest.
            if (State == GuardState.Locked
                && _config.Guard.UnlockPolicy == UnlockPolicy.KeyAndPassphrase)
            {
                _surface.SetStatus("Key removed — insert it, then enter the passphrase.");
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
                    Log(stale
                        ? "Keyfile presented a previous-generation secret — " +
                          "possible clone or interrupted rotation."
                        : "Keyfile attestation mismatch — config.json " +
                          "tampered or the keyfile was forged.");
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
                            => "Key verified — enter the passphrase.",
                        UnlockPolicy.KeyAndPassphrase
                            => "Stale keyfile — passphrase required.",
                        UnlockPolicy.KeyOnly
                            => "Stale keyfile — attempting repair (re-enroll if it persists).",
                        _ => "Stale keyfile — type the passphrase.",
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
                _surface.SetStatus($"CryptoKey detected — {check.Detail}. Or type the passphrase.");
            }
        }
        EmitSnapshot();
    }

    /// <summary>
    /// Forced rotation outside the edge/throttle gate — the passphrase-change
    /// path uses it to re-attest (the MAC covers the passphrase hash, so a
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
                try { _monitor.BeginInvoke(new Action(() => lines.ForEach(Log))); }
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

    private void OnPassphraseSubmitted(string attempt)
    {
        // This runs inside the low-level keyboard hook — return instantly or
        // the hook times out and keystrokes leak through unswallowed. PBKDF2
        // runs off-thread and the result is marshaled back to the UI.

        // Belt-and-braces: the hook drops input during cooldown, but an Enter
        // queued just before the freeze could still land here.
        if (_cooldownUntil is DateTime until && DateTime.Now < until)
            return;

        UnlockPolicy policy = _config.Guard.UnlockPolicy;
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

            try
            {
                _monitor.BeginInvoke(new Action(() => OnPassphraseResult(ok, policy)));
            }
            catch (Exception)
            {
                // UI thread is gone — the process is exiting anyway.
            }
        });
    }

    private void OnPassphraseResult(bool ok, UnlockPolicy policy)
    {
        if (!ok)
        {
            _failedAttempts++;
            _surface.SetFailedAttempts(_failedAttempts);
            // Exponential cooldown: fails 1-2 free, then 15s/30s/60s/120s/…
            // capped at 300s. Enforced in the hook so mashing can't pile up.
            if (_failedAttempts >= 3)
            {
                int secs = Math.Min(15 << Math.Min(_failedAttempts - 3, 5), 300);
                var until = DateTime.Now.AddSeconds(secs);
                _cooldownUntil = until;
                _surface.SetCooldown(until);
                _surface.SetStatus($"Too many attempts — input frozen for {secs}s.");
                Log($"Passphrase failed attempt #{_failedAttempts} — input frozen {secs}s.");
            }
            else
            {
                _surface.SetStatus("Incorrect passphrase — try again.");
            }
            return;
        }

        // Correct passphrase — now the policy gate decides.
        _failedAttempts = 0;
        _cooldownUntil = null;
        _surface.SetCooldown(null);
        _surface.SetFailedAttempts(0);

        if (policy == UnlockPolicy.KeyOnly)
        {
            _surface.SetStatus("Passphrase is disabled — insert the key.");
            return;
        }
        if (policy == UnlockPolicy.KeyAndPassphrase && !_keyVerifiedNow)
        {
            // Break-glass: under strict tamper a stale key never counts as
            // the factor, but the passphrase remains an explicit failsafe —
            // the unlock happens WITH the tamper alarm already raised.
            if (_config.Guard.StrictTamper && _staleKeyPresent)
            {
                Log("Break-glass unlock — passphrase accepted over a stale keyfile.");
                UnlockNow();
            }
            else
            {
                _surface.SetStatus("Passphrase correct — insert your key first.");
            }
            return;
        }
        Log("Unlocked via failsafe passphrase — re-locks on next key removal.");
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
        Log($"LOCKED — {reason}.");
        SetState(GuardState.Locked);
        // Secure first; any engage failure falls back to the classic overlay —
        // the lock must always land.
        EnsureSurfaceMode();
        bool engaged = _surface.Engage();
        if (!engaged && _surface is SecureLockSurface secure)
        {
            Log($"Secure desktop failed to engage ({secure.EngageError ?? "unknown"}).");
            SwitchToClassic();
            engaged = _surface.Engage();
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
        Log("Unlocked.");
        // Cooldown dies with the lock session — in-memory only per design.
        _cooldownUntil = null;
        _surface.SetCooldown(null);
        // Disengage returns input (and the input desktop) before teardown.
        _surface.Disengage();
        SetState(GuardState.Unlocked);
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
        _surface.Dispose();
        _monitor.Dispose();
    }
}
