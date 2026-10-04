using System.Diagnostics;

namespace CryptoKey;

/// <summary>
/// Secure lock surface: a private Windows desktop ("CryptoKeyLock") that the
/// session is switched onto while locked. Nothing else exists there — no
/// taskbar, no apps, no focus to steal, and Task Manager can't see the form.
/// Input containment is structural; the low-level hooks still run on the
/// lock thread to feed the passphrase buffer and arm the panic combo.
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
    public event Action<string>? PassphraseSubmitted;
    public event Action? PanicRequested;

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

    /// <summary>Why the last Engage failed (for the caller's fallback log line).</summary>
    public string? EngageError => _engageError;

    /// <summary>
    /// Builds the private desktop + lock thread, then flips the session onto
    /// it. False on any failure — the caller engages the classic surface.
    /// </summary>
    public bool Engage()
    {
        lock (_engageSync)
            return EngageCore();
    }

    private bool EngageCore()
    {
        // _engaged (not _form) is authoritative: _form clears in the lock
        // thread's finally, which can lag behind a Join — a stale non-null
        // form would make this a silent no-op.
        if (_engaged)
            return true;

        // Capture the user's input desktop BEFORE anything can switch —
        // without this there is no guaranteed way back.
        _hInput = NativeMethods.OpenInputDesktop(0, false, NativeMethods.DESKTOP_SWITCHDESKTOP);
        if (_hInput == IntPtr.Zero)
        {
            _engageError = "OpenInputDesktop failed";
            return false;
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
            _engageError = "SwitchDesktop failed";
            TearDownLockThread();
            return false;
        }
        _engaged = true;
        return true;
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
            _ready.Set();
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
            try { _locker?.Dispose(); } catch (Exception) { }
            try { _form?.Dispose(); } catch (Exception) { }
            _form = null;
            _locker = null;
            // The pump died while still "engaged" — the user is now staring
            // at a blank private desktop with no lock form. Pull them back;
            // _abandoned means the teardown path already handled the return.
            if (!_abandoned)
                ReleaseInput();
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

    /// <summary>Back to the user's desktop, then the lock thread dies.</summary>
    public void Disengage()
    {
        lock (_engageSync)
        {
            _engaged = false;
            SwitchBack();
            TearDownLockThread();
            CloseInputHandle();
        }
    }

    /// <summary>
    /// Fail-dead: restore the input desktop FIRST — even if the unhook below
    /// fails, containment ends. Then best-effort unhook (safe cross-thread;
    /// if the lock thread already died its hooks died with it).
    /// </summary>
    public void ReleaseInput()
    {
        SwitchBack();
        try { _locker?.Unlock(); }
        catch (Exception) { }
    }

    /// <summary>Nothing else exists on the lock desktop — no clip to re-assert.</summary>
    public void ReassertClip() { }

    private void SwitchBack()
    {
        if (_hInput != IntPtr.Zero)
            NativeMethods.SwitchDesktop(_hInput); // idempotent
    }

    private void TearDownLockThread()
    {
        _abandoned = true;
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

    public void Dispose()
    {
        Disengage();
        if (_hLock != IntPtr.Zero)
        {
            NativeMethods.CloseDesktop(_hLock);
            _hLock = IntPtr.Zero;
        }
        _ready.Dispose();
    }
}
