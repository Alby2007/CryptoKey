using System.Diagnostics;
using System.Runtime.InteropServices;

namespace CryptoKey;

/// <summary>
/// Secure lock surface: a private Windows desktop ("CryptoKeyLock") that the
/// session is switched onto while locked. Nothing else exists there — no
/// taskbar, no apps, no focus to steal, and Task Manager can't see the form.
/// Input containment is structural; the low-level hooks still run on the
/// lock thread to feed the phrase buffer and arm the panic combo.
///
/// Lifecycle: Engage captures the user's input desktop BEFORE switching,
/// spawns an STA lock thread (SetThreadDesktop is its first statement),
/// waits for "form shown + hooks installed", then SwitchDesktop(hLock).
/// Disengage switches back FIRST, then tears the lock thread down.
/// ReleaseInput (fail-dead, any thread) switches back and unhooks without
/// waiting on anything.
/// </summary>
internal sealed class SecureLockSurface : ILockSurface
{
    public event Action<char[]>? PassphraseSubmitted;
    public event Action? PanicRequested;
    public event Action<string>? SecurityEvent;

    private const string DesktopName = "CryptoKeyLock";

    private readonly bool _devMode;
    private readonly object _engageSync = new(); // Engage/Disengage single-flight
    private IntPtr _hLock;          // created once, kept for process life
    private IntPtr _hInput;         // user's input desktop, captured per engage
    private Thread? _lockThread;
    private readonly ManualResetEventSlim _ready = new();
    private volatile string? _engageError;
    private volatile bool _abandoned;
    private volatile bool _engaged; // authoritative "session is switched" flag
    private Process? _watchdog;     // dead-man's switch for the switched session
    private Thread? _flapThread;          // started once — lives for the surface's lifetime
    private volatile bool _surfaceDead;   // Dispose's exit signal for the flap thread
    private readonly FlapCounter _flapCounter = new();
    private bool _stormAnnounced;         // storm edge — alert once per burst, not per flap

    // Created and owned on the lock thread — never touch directly except
    // through InvokeOnLock (or from the lock thread itself).
    private LockForm? _form;
    private InputLocker? _locker;

    // Mirrored UI state — setters may fire while the surface is disengaged
    // (or before the lock thread finishes building), so each one is pushed
    // onto the form at creation time too.
    private bool _animations = true;
    private string? _status;
    private bool _statusIsDefault = true;
    private int _passLen;
    private int _attempts;
    private DateTime? _cooldownUntil;

    public SecureLockSurface(bool devMode) => _devMode = devMode;

    /// <summary>Secure tier — GuardService falls back to the overlay when Engage fails.</summary>
    public bool IsOverlay => false;

    /// <summary>Why the last Engage failed (for the caller's fallback log line).</summary>
    public string? EngageError => _engageError;

    /// <summary>
    /// Builds the private desktop + lock thread, then flips the session onto
    /// it. False on any failure — the caller engages the classic surface.
    /// </summary>
    public bool Engage()
    {
        lock (_engageSync)
        {
            try
            {
                return EngageCore();
            }
            catch (Exception ex)
            {
                // Contain everything — the caller falls back to the overlay.
                // If the session somehow got switched first, try to pull it
                // back; if THAT fails, leave the lock thread + watchdog alive
                // rather than tear down onto a stranded desktop.
                _engageError = ex.Message;
                try
                {
                    if (!SwitchBack())
                        return false;
                    TearDownLockThread();
                }
                catch (Exception) { }
                CloseInputHandle();
                return false;
            }
        }
    }

    private bool EngageCore()
    {
        // _engaged (not _form) is authoritative: _form clears in the lock
        // thread's finally, which can lag behind a Join — a stale non-null
        // form would make this a silent no-op.
        if (_engaged)
            return true;
        // A previous attempt can leave a live lock thread behind (exception
        // after spawn where the switch-back also failed). If it's still
        // running the lock is effectively engaged — don't double-spawn.
        if (_lockThread?.IsAlive == true)
            return true;

        // Capture the user's input desktop BEFORE anything can switch —
        // without this there is no guaranteed way back. Kept across retries:
        // a non-zero handle is the verified "home" from a previous engage
        // that never made it back — re-capturing now could grab the lock
        // desktop itself and lose the way home.
        if (_hInput == IntPtr.Zero)
        {
            _hInput = NativeMethods.OpenInputDesktop(0, false,
                NativeMethods.DESKTOP_SWITCHDESKTOP | NativeMethods.DESKTOP_READOBJECTS);
            if (_hInput == IntPtr.Zero)
            {
                _engageError = "OpenInputDesktop failed";
                return false;
            }
            // The user is on the Winlogon SAS screen (Ctrl+Alt+Del) — yanking
            // them out of it is wrong, and switching back to it later is
            // equally wrong. Bail to the classic overlay for this lock.
            string? deskName = GetDesktopName(_hInput);
            if (deskName != null && deskName.Equals("Winlogon", StringComparison.OrdinalIgnoreCase))
            {
                _engageError = "input desktop is Winlogon (secure attention screen up)";
                CloseInputHandle();
                return false;
            }
        }

        if (_hLock == IntPtr.Zero)
        {
            _hLock = NativeMethods.CreateDesktop(DesktopName, IntPtr.Zero, IntPtr.Zero,
                0, NativeMethods.DESKTOP_ALL, IntPtr.Zero);
            if (_hLock == IntPtr.Zero)
            {
                _engageError = "CreateDesktop failed";
                CloseInputHandle();
                return false;
            }
        }

        _ready.Reset();
        _engageError = null;
        _abandoned = false;
        _lockThread = new Thread(LockThreadMain)
        {
            IsBackground = true,
            Name = "CryptoKey.Lock",
        };
        _lockThread.SetApartmentState(ApartmentState.STA);
        _lockThread.Start();

        if (!_ready.Wait(5000))
        {
            _engageError ??= "lock thread timed out";
            TearDownLockThread();
            return false;
        }
        if (_engageError != null)
        {
            TearDownLockThread();
            return false;
        }

        // The watchdog must exist BEFORE the session switches — a crash
        // during/right-after the switch is exactly what it covers. No
        // watchdog, no switch.
        if (!SpawnWatchdog())
        {
            TearDownLockThread();
            return false;
        }

        if (!NativeMethods.SwitchDesktop(_hLock))
        {
            _engageError = $"SwitchDesktop failed (err {Marshal.GetLastWin32Error()})";
            TearDownLockThread();
            return false;
        }
        _engaged = true;
        StartFlapMonitor();
        return true;
    }

    /// <summary>
    /// Desktop-flap monitor (~300ms): --release-desktop's mechanism is also
    /// the attack — any same-session process can SwitchDesktop input away
    /// from CryptoKeyLock without touching a hook or killing anything.
    /// Foreign input desktops get yanked back inside a tick; a storm (≥3
    /// in 10s) escalates to LockWorkStation — the attacker lands on real
    /// Windows auth their script can't answer.
    ///
    /// The tick runs under _engageSync: Disengage holds it through
    /// SwitchBack + _engaged=false, so a legit unlock is never misread as
    /// a flap. ReleaseInput clears _engaged before its switch-back retries
    /// — covered by the re-check right before any re-switch.
    /// </summary>
    private void StartFlapMonitor()
    {
        _flapCounter.Reset();
        _stormAnnounced = false;
        if (_flapThread != null)
            return; // one thread for the surface's lifetime — re-engage just un-parks it
        _flapThread = new Thread(FlapMonitorMain)
        {
            IsBackground = true,
            Name = "CryptoKey.Flap",
        };
        _flapThread.Start();
    }

    private void FlapMonitorMain()
    {
        while (!_surfaceDead)
        {
            Thread.Sleep(300);
            // A bad tick must never kill this thread — it's the surface's
            // only monitor and StartFlapMonitor won't respawn it.
            try
            {
                if (!_engaged)
                    continue; // volatile fast-path — no lock churn while unlocked

                // Classify, re-switch, and count under the lock; raise events
                // AFTER releasing it — handlers must never run inside
                // _engageSync (Monitor reentrancy would let a callback run
                // surface teardown on this thread).
                string? flapEvent = null, stormEvent = null;
                bool stormNow = false;
                lock (_engageSync)
                {
                    if (!_engaged)
                        continue;
                    IntPtr h = NativeMethods.OpenInputDesktop(0, false,
                        NativeMethods.DESKTOP_READOBJECTS);
                    bool openFailed = h == IntPtr.Zero;
                    string? name = null;
                    if (!openFailed)
                    {
                        name = GetDesktopName(h);
                        NativeMethods.CloseDesktop(h);
                    }
                    if (!FlapPolicy.IsHostile(name, openFailed))
                        continue;
                    if (!_engaged)
                        continue; // ReleaseInput switched back mid-open — don't fight it
                    NativeMethods.SwitchDesktop(_hLock);
                    flapEvent = "desktop-flap";
                    if (_flapCounter.Record(DateTime.UtcNow))
                    {
                        stormNow = true; // stay pinned at OS auth — fires per flap, idempotent
                        if (!_stormAnnounced)
                        {
                            _stormAnnounced = true; // edge only — a sustained attack
                            stormEvent = "desktop-flap-storm"; // shouldn't push-spam
                        }
                    }
                    else
                    {
                        _stormAnnounced = false; // aged out — a fresh burst re-alerts
                    }
                }
                if (flapEvent != null)
                    SecurityEvent?.Invoke(flapEvent);
                if (stormEvent != null)
                    SecurityEvent?.Invoke(stormEvent);
                if (stormNow)
                    NativeMethods.LockWorkStation();
            }
            catch (Exception) { }
        }
    }

    /// <summary>
    /// Dead-man's switch: `cryptokey --lock-watchdog &lt;pid&gt;` waits on this
    /// process and SwitchDesktops back to Default if we die. Windows does NOT
    /// return the input desktop itself when the owner process is killed —
    /// verified empirically; without this a crash strands the user.
    /// </summary>
    private bool SpawnWatchdog()
    {
        try
        {
            _watchdog = Process.Start(new ProcessStartInfo(
                Environment.ProcessPath ?? Application.ExecutablePath,
                $"--lock-watchdog {Environment.ProcessId}")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            }) ?? throw new InvalidOperationException("watchdog did not start");
            return true;
        }
        catch (Exception ex)
        {
            _engageError = $"watchdog spawn failed ({ex.Message})";
            return false;
        }
    }

    private void StopWatchdog()
    {
        Process? p = _watchdog;
        _watchdog = null;
        if (p == null)
            return;
        try { if (!p.HasExited) p.Kill(); }
        catch (Exception) { }
        p.Dispose();
    }

    /// <summary>STA lock thread: own desktop, own hooks, own form, own pump.</summary>
    private void LockThreadMain()
    {
        try
        {
            // Must be the first statement — any window or hook created before
            // this lands on the WRONG desktop.
            if (!NativeMethods.SetThreadDesktop(_hLock))
            {
                _engageError = "SetThreadDesktop failed";
                _ready.Set();
                return;
            }
            _locker = new InputLocker(_devMode);
            _locker.PassphraseSubmitted += s => PassphraseSubmitted?.Invoke(s);
            _locker.PanicRequested += () => PanicRequested?.Invoke();
            _locker.PassphraseLengthChanged += n =>
            {
                try { _form?.SetPassphraseLength(n); }
                catch (Exception) { }
            };
            if (!_locker.Lock() && !_locker.Lock())
            {
                _engageError = "input hooks failed on lock thread";
                _ready.Set();
                return;
            }

            _form = new LockForm(SystemInformation.VirtualScreen, primary: true);
            PushMirroredState(_form);
            _form.Show();
            // Signal ready through the queue — it only fires once the pump
            // is actually processing, which the LL hooks require. Setting
            // it synchronously would let Engage switch the session a beat
            // before input is swallowed.
            _form.BeginInvoke(new Action(() => _ready.Set()));
            // Own pump for this thread; Application.Run(form) returns when
            // the form closes (teardown path).
            if (!_abandoned)
                Application.Run(_form);
        }
        catch (Exception ex)
        {
            _engageError = ex.Message;
            _ready.Set();
        }
        finally
        {
            // The pump died while still "engaged" — the user is now staring
            // at a blank private desktop with no lock form. Pull them back
            // FIRST, while the locker/form still exist; _abandoned means the
            // teardown path already handled the return.
            if (!_abandoned)
                ReleaseInput();
            try { _locker?.Dispose(); } catch (Exception) { }
            try { _form?.Dispose(); } catch (Exception) { }
            _form = null;
            _locker = null;
        }
    }

    private void PushMirroredState(LockForm f)
    {
        f.SetAnimations(_animations);
        if (!_statusIsDefault && _status != null)
            f.SetStatus(_status);
        f.SetPassphraseLength(_passLen);
        f.SetFailedAttempts(_attempts);
        f.SetCooldown(_cooldownUntil);
    }

    /// <summary>
    /// Back to the user's desktop, then the lock thread dies. False when the
    /// switch-back failed — the session is STILL on the lock desktop then,
    /// so nothing is torn down: the lock keeps working (form, hooks,
    /// watchdog) and the next Disengage retries the switch.
    /// </summary>
    public bool Disengage()
    {
        lock (_engageSync)
        {
            if (!SwitchBack())
            {
                _engageError = "SwitchDesktop back to the input desktop failed";
                return false;
            }
            _engaged = false;
            TearDownLockThread();
            CloseInputHandle();
            return true;
        }
    }

    /// <summary>
    /// Fail-dead: restore the input desktop FIRST — even if the unhook below
    /// fails, containment ends. Then best-effort unhook (safe cross-thread;
    /// if the lock thread already died its hooks died with it). Clears
    /// _engaged first — reaching here with the flag stale is what made a
    /// dead lock pump report "still engaged" forever.
    /// </summary>
    public void ReleaseInput()
    {
        _engaged = false;
        // Bounded retry — the session is stranded until this switch lands.
        // If it still fails, keep the watchdog alive (fires on process
        // death) rather than kill the last rescue path.
        bool back = SwitchBack();
        for (int i = 0; i < 3 && !back; i++)
        {
            Thread.Sleep(200);
            back = SwitchBack();
        }
        if (!back)
            return;
        try { _locker?.Unlock(); }
        catch (Exception) { }
        StopWatchdog();
    }

    /// <summary>Nothing else exists on the lock desktop — no clip to re-assert.</summary>
    public void ReassertClip() { }

    /// <returns>false when the session could not be switched back.</returns>
    private bool SwitchBack()
    {
        return _hInput == IntPtr.Zero || NativeMethods.SwitchDesktop(_hInput);
    }

    private void TearDownLockThread()
    {
        _abandoned = true;
        // The flap thread outlives the engagement — it idles on _engaged
        // and resets its counter at the next StartFlapMonitor.
        StopWatchdog();
        LockForm? f = _form;
        if (f != null)
        {
            try
            {
                if (f.IsHandleCreated)
                    f.BeginInvoke(() =>
                    {
                        try { _locker?.Unlock(); } catch (Exception) { }
                        f.Close();
                    });
            }
            catch (Exception) { }
        }
        Thread? t = _lockThread;
        if (t != null && Thread.CurrentThread != t)
            t.Join(2500);
        _lockThread = null;
        CloseInputHandle();
    }

    private void CloseInputHandle()
    {
        if (_hInput != IntPtr.Zero)
        {
            NativeMethods.CloseDesktop(_hInput);
            _hInput = IntPtr.Zero;
        }
    }

    // Cross-thread marshal into the lock thread. Anything touching _locker is
    // wrapped in the same delegate so it runs ON the lock thread.
    private void InvokeOnLock(Action<LockForm> action)
    {
        LockForm? f = _form;
        if (f == null)
            return;
        try
        {
            if (f.IsHandleCreated)
                f.BeginInvoke(() => action(f));
        }
        catch (Exception) { }
    }

    public void SetAnimations(bool enabled)
    {
        _animations = enabled;
        InvokeOnLock(f => f.SetAnimations(enabled));
    }

    public void SetStatus(string message)
    {
        _status = message;
        _statusIsDefault = false;
        InvokeOnLock(f => f.SetStatus(message));
    }

    public void ResetStatus()
    {
        _status = null;
        _statusIsDefault = true;
        InvokeOnLock(f => f.ResetStatus());
    }

    public void SetPassphraseLength(int len)
    {
        _passLen = len;
        InvokeOnLock(f => f.SetPassphraseLength(len));
    }

    public void SetFailedAttempts(int count)
    {
        _attempts = count;
        InvokeOnLock(f => f.SetFailedAttempts(count));
    }

    public void SetCooldown(DateTime? until)
    {
        _cooldownUntil = until;
        InvokeOnLock(f =>
        {
            f.SetCooldown(until);
            try { _locker?.SetCooldownUntil(until); }
            catch (Exception) { }
        });
    }

    /// <summary>UOI_NAME for a desktop handle, or null if it can't be read.</summary>
    private static string? GetDesktopName(IntPtr hDesktop)
    {
        NativeMethods.GetUserObjectInformation(hDesktop, NativeMethods.UOI_NAME,
            IntPtr.Zero, 0, out int needed);
        if (needed <= 0)
            return null;
        IntPtr buf = Marshal.AllocHGlobal(needed);
        try
        {
            return NativeMethods.GetUserObjectInformation(hDesktop, NativeMethods.UOI_NAME,
                buf, needed, out _)
                ? Marshal.PtrToStringUni(buf) : null;
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }

    public void Dispose()
    {
        _surfaceDead = true;
        try { Disengage(); }
        catch (Exception) { }
        if (_hLock != IntPtr.Zero)
        {
            NativeMethods.CloseDesktop(_hLock);
            _hLock = IntPtr.Zero;
        }
        _ready.Dispose();
    }
}
