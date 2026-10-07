namespace CryptoKey;

/// <summary>
/// Classic lock surface: the on-desktop overlay. Composes the existing
/// <see cref="LockScreen"/> (per-monitor forms + topmost watchdog) and
/// <see cref="InputLocker"/> (low-level hooks).
///
/// Threading: the forms live on the engine thread (built in the ctor,
/// pumped by the app pump — a stalled engine only delays repaints). The
/// HOOKS get a dedicated pump thread per engagement: the engine thread is
/// also where keyfile reads, IPC, and crypto run — a stall there used to
/// silence the hooks long enough for Windows to quietly unhook them,
/// leaking input to the desktop behind the overlay. A hook thread that
/// does nothing but pump can't starve.
/// </summary>
internal sealed class ClassicLockSurface : ILockSurface
{
    public event Action<char[]>? PassphraseSubmitted;
    public event Action? PanicRequested;

    /// <summary>Never fires — the overlay has no private desktop to flap.</summary>
    public event Action<string>? SecurityEvent
    {
        add { }
        remove { }
    }

    private readonly InputLocker _input;
    private readonly LockScreen _lock;
    private string? _engageError;
    private volatile bool _engaged; // true while the hook thread holds input

    private Thread? _hookThread;
    private readonly ManualResetEventSlim _hooksReady = new(false);
    private uint _hookThreadId; // written on the pump thread, read at teardown

    public ClassicLockSurface(bool devMode)
    {
        _input = new InputLocker(devMode);
        _lock = new LockScreen();
        _input.PassphraseLengthChanged += len => _lock.SetPassphraseLength(len);
        _input.PassphraseSubmitted += s => PassphraseSubmitted?.Invoke(s);
        _input.PanicRequested += () => PanicRequested?.Invoke();
        _lock.ReassertTick += () => _input.ReassertClip();
    }

    /// <summary>Overlay tier — this IS the fallback.</summary>
    public bool IsOverlay => true;

    /// <summary>Why the last Engage failed — overlay failures are hook failures.</summary>
    public string? EngageError => _engageError;

    /// <summary>Overlay on this thread; hooks on their own pump thread.</summary>
    public bool Engage()
    {
        if (_engaged)
            return true;
        _engageError = null;
        _hooksReady.Reset();
        _hookThread = new Thread(HookThreadMain)
        {
            IsBackground = true,
            Name = "CryptoKey.Hooks",
        };
        _hookThread.SetApartmentState(ApartmentState.STA);
        _hookThread.Start();
        // The ready flag is raised by a message dispatched THROUGH the
        // pump — it proves hooks are installed AND the loop is live, so
        // the overlay never becomes visible before input is swallowed.
        if (!_hooksReady.Wait(5000))
        {
            _engageError ??= "hook pump failed to start";
            StopHookThread();
            return false;
        }
        if (_engageError != null)
        {
            StopHookThread();
            return false;
        }
        _engaged = true;
        _lock.SetFailedAttempts(0);
        _lock.Show();
        return true;
    }

    /// <summary>
    /// Pump thread: installs the hooks, then blocks in GetMessage — LL hook
    /// callbacks only dispatch while a message loop runs. Readiness is
    /// signaled by a self-posted marker that only drains once the loop is
    /// actually processing (mirrors SecureLockSurface's BeginInvoke probe).
    /// </summary>
    private void HookThreadMain()
    {
        _hookThreadId = NativeMethods.GetCurrentThreadId();
        try
        {
            if (!_input.Lock() && !_input.Lock())
            {
                _engageError = "low-level input hooks refused to install";
                _hooksReady.Set();
                return;
            }
            if (!NativeMethods.PostThreadMessage(_hookThreadId,
                    NativeMethods.WM_CK_READY, UIntPtr.Zero, IntPtr.Zero))
            {
                _engageError = "hook pump priming failed";
                _hooksReady.Set();
                return;
            }
            var msg = new NativeMethods.MSG();
            while (NativeMethods.GetMessage(ref msg, IntPtr.Zero, 0, 0) > 0)
            {
                if (msg.message == NativeMethods.WM_CK_READY)
                {
                    _hooksReady.Set();
                    continue;
                }
                NativeMethods.TranslateMessage(ref msg);
                NativeMethods.DispatchMessage(ref msg);
            }
        }
        catch (Exception ex)
        {
            _engageError = ex.Message;
            _hooksReady.Set();
        }
        finally
        {
            _input.Unlock();
            _hookThreadId = 0;
        }
    }

    /// <summary>Post WM_QUIT and wait — bounded, so a wedged pump can't hang teardown.</summary>
    private void StopHookThread()
    {
        uint tid = _hookThreadId;
        if (tid != 0)
            NativeMethods.PostThreadMessage(tid, NativeMethods.WM_QUIT,
                UIntPtr.Zero, IntPtr.Zero);
        _hookThread?.Join(3000);
        _hookThread = null;
    }

    /// <summary>Always succeeds — the overlay can't strand a session.</summary>
    public bool Disengage()
    {
        _engaged = false;
        StopHookThread();
        _lock.Hide();
        return true;
    }

    /// <summary>
    /// Fail-dead (fatal policy only — normal teardown uses Disengage).
    /// The classic tier has no lock-watchdog: a crash while locked used to
    /// release input onto an open desktop. When the overlay was actually
    /// engaged, pin the session at OS auth instead.
    /// </summary>
    public void ReleaseInput()
    {
        bool wasEngaged = _engaged;
        _engaged = false;
        StopHookThread();
        if (wasEngaged)
        {
            try { NativeMethods.LockWorkStation(); }
            catch (Exception) { }
        }
    }

    public void ReassertClip() => _input.ReassertClip();

    public void SetAnimations(bool enabled) => _lock.SetAnimations(enabled);

    public void SetStatus(string message) => _lock.SetStatus(message);

    public void ResetStatus() => _lock.ResetStatus();

    public void SetPassphraseLength(int len) => _lock.SetPassphraseLength(len);

    public void SetFailedAttempts(int count) => _lock.SetFailedAttempts(count);

    public void SetCooldown(DateTime? until)
    {
        _input.SetCooldownUntil(until);
        _lock.SetCooldown(until);
    }

    public void Dispose()
    {
        StopHookThread();
        _input.Dispose();
        _lock.Dispose();
    }
}
