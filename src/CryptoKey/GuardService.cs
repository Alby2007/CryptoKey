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
    private readonly InputLocker _input;
    private readonly LockScreen _lock;

    private UsbDisk? _lastDisk;
    private string? _lastVerifyFailure;
    private DateTime? _pausedUntil;
    private int _failedAttempts;
    private StatusSnapshot? _lastSnapshot;
    private bool _verifiedEdge;
    private DateTime _lastRotateAttemptUtc = DateTime.MinValue;
    private string? _tamperNote;

    public GuardService(KeyConfig config, bool devMode)
    {
        _config = config;
        _monitor = new UsbMonitor(config.DeviceSerial);
        _input = new InputLocker(devMode);
        _lock = new LockScreen();

        _monitor.PresenceChanged += OnPresenceChanged;
        _monitor.PresenceChecked += OnPresenceChecked;
        _monitor.ErrorLogged += Log;
        _input.PassphraseSubmitted += OnPassphraseSubmitted;
        _input.PassphraseLengthChanged += len => _lock.SetPassphraseLength(len);
        _lock.ReassertTick += () => _input.ReassertClip();
        _input.PanicRequested += () =>
        {
            Log("Panic combo (Ctrl+Alt+Shift+F12) — exiting.");
            Application.Exit();
        };
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
        _lock.SetAnimations(_config.Guard.Animations);
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
            _pausedUntil, _tamperNote);

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
                       $"tamper=\"{s.TamperNote ?? "-"}\"";
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

    /// <summary>Live-apply the reduce-motion setting to the lock overlay.</summary>
    public void ApplyMotion(bool enabled) => _lock.SetAnimations(enabled);

    /// <summary>Immediately drop the input hooks and cursor clip (fatal-error path).</summary>
    public void ReleaseInput() => _input.Unlock();

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
            EmitSnapshot();
            return;
        }

        KeyfileCheck check = KeyVerifier.Check(_config, disk);
        if (check.Match != SecretMatch.None)
        {
            _lastVerifyFailure = null;
            bool edgeFlip = !_verifiedEdge;
            _verifiedEdge = true;

            if (check.Match == SecretMatch.Previous)
            {
                // Accepted (also the interrupted-rotation case) but loud —
                // a replayed old secret is what a clone looks like.
                _tamperNote = "possible clone — stale keyfile replayed";
                Log("Keyfile presented a previous-generation secret — " +
                    "possible clone or interrupted rotation.");
            }
            else
            {
                _tamperNote = null;
            }

            if (State == GuardState.Locked)
                UnlockNow();

            // Burn the secret once per key session (edge), and whenever a
            // stale file shows up (heals interrupted rotations), throttled.
            if ((edgeFlip || check.Match == SecretMatch.Previous)
                && DateTime.UtcNow - _lastRotateAttemptUtc > TimeSpan.FromSeconds(5))
            {
                _lastRotateAttemptUtc = DateTime.UtcNow;
                TryRotate(disk);
            }
        }
        else
        {
            _verifiedEdge = false;
            _tamperNote = null;
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
                _lock.SetStatus($"CryptoKey detected — {check.Detail}. Or type the passphrase.");
            }
        }
        EmitSnapshot();
    }

    /// <summary>
    /// Single-use ratchet: burn the secret the drive presented. Config first,
    /// then the drive — a crash anywhere leaves the drive on the previous
    /// generation, which still verifies as stale and heals on the next pass.
    /// </summary>
    private void TryRotate(UsbDisk disk)
    {
        byte[] next = RandomNumberGenerator.GetBytes(64);

        string oldSecret = _config.SecretHash, oldPrev = _config.PrevSecretHash;
        int oldCount = _config.RotationCount;
        DateTime? oldRot = _config.LastRotationUtc;
        ConfigStore.RotateSecret(_config, next);
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
            return;
        }

        List<string> results;
        try
        {
            results = KeyVerifier.RotateKeyfiles(disk, next);
        }
        catch (Exception ex)
        {
            Log($"Rotation write failed ({ex.Message}) — drive is stale, heals on retry.");
            return;
        }
        if (results.Count == 0)
            Log($"Config rotated to generation {_config.RotationCount} but no keyfile " +
                "found on the drive — the drive secret is stale until it reappears.");
        else if (results.All(r => r.EndsWith("ok")))
            Log($"Keyfile rotated to generation {_config.RotationCount}.");
        else
            Log($"Rotated to generation {_config.RotationCount} with issues: " +
                string.Join("; ", results) + ".");
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
                _monitor.BeginInvoke(new Action(() =>
                {
                    if (ok)
                    {
                        Log("Unlocked via failsafe passphrase — re-locks on next key removal.");
                        UnlockNow();
                    }
                    else
                    {
                        _failedAttempts++;
                        _lock.SetFailedAttempts(_failedAttempts);
                        _lock.SetStatus("Incorrect passphrase — try again.");
                    }
                }));
            }
            catch (Exception)
            {
                // UI thread is gone — the process is exiting anyway.
            }
        });
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
        Log($"LOCKED — {reason}.");
        SetState(GuardState.Locked);
        // One retry: a failed attempt unrolls its own partial state first.
        bool hooked = _input.Lock() || _input.Lock();
        if (!hooked)
        {
            Log("WARNING: input hooks failed — INPUT IS NOT BLOCKED.");
            _lock.SetStatus("WARNING: input hooks failed — screen only. Ctrl+Alt+Del to recover.");
        }
        else
        {
            _lock.ResetStatus();
        }
        _lock.SetFailedAttempts(0);
        _lock.Show();
    }

    private void UnlockNow()
    {
        if (State != GuardState.Locked)
            return;
        _lastVerifyFailure = null;
        Log("Unlocked.");
        _input.Unlock();
        _lock.Hide();
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

    private void Log(string message)
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
        _input.Dispose();
        _lock.Dispose();
        _monitor.Dispose();
    }
}
