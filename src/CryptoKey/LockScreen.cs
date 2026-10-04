namespace CryptoKey;

/// <summary>
/// Classic lock surface: one <see cref="LockForm"/> per monitor on the user's
/// own desktop, plus a 250ms watchdog that re-asserts topmost to fight focus
/// stealers and re-covers newly attached displays. The secure-desktop
/// alternative lives in <see cref="SecureLockSurface"/>.
/// </summary>
internal sealed class LockScreen : IDisposable
{
    private const string DefaultStatus =
        "Insert your CryptoKey, or type the failsafe passphrase and press Enter.";

    /// <summary>Raised after each topmost re-assert (lets the input locker re-clip).</summary>
    public event Action? ReassertTick;

    private readonly List<LockForm> _forms = new();
    private readonly System.Windows.Forms.Timer _topmostTimer;
    private bool _visible;
    private bool _animations = true;
    private string _status = DefaultStatus;
    private int _passLen;
    private int _failedAttempts;
    private DateTime? _cooldownUntil;

    public LockScreen()
    {
        BuildForms();

        _topmostTimer = new System.Windows.Forms.Timer { Interval = 250 };
        _topmostTimer.Tick += (_, _) =>
        {
            EnsureCoverage();
            ReassertTopmost();
        };
    }

    public void Show()
    {
        EnsureCoverage();
        _visible = true;
        foreach (LockForm f in _forms)
            f.Show();
        ReassertTopmost();
        _topmostTimer.Start();
    }

    public void Hide()
    {
        _visible = false;
        _topmostTimer.Stop();
        foreach (LockForm f in _forms)
            f.Hide();
    }

    public void SetAnimations(bool enabled)
    {
        _animations = enabled;
        foreach (LockForm f in _forms)
            f.SetAnimations(enabled);
    }

    public void SetPassphraseLength(int len)
    {
        _passLen = len;
        foreach (LockForm f in _forms)
            f.SetPassphraseLength(len);
    }

    public void SetStatus(string message)
    {
        _status = message;
        foreach (LockForm f in _forms)
            f.SetStatus(message);
    }

    public void SetFailedAttempts(int count)
    {
        _failedAttempts = count;
        foreach (LockForm f in _forms)
            f.SetFailedAttempts(count);
    }

    /// <summary>Passphrase-input freeze deadline — countdown paints live until expiry.</summary>
    public void SetCooldown(DateTime? until)
    {
        _cooldownUntil = until;
        foreach (LockForm f in _forms)
            f.SetCooldown(until);
    }

    private void BuildForms()
    {
        Screen[] screens = Screen.AllScreens;
        for (int i = 0; i < screens.Length; i++)
        {
            var f = new LockForm(screens[i].Bounds, i == 0);
            f.SetAnimations(_animations);
            f.SetStatus(_status);
            f.SetPassphraseLength(_passLen);
            f.SetFailedAttempts(_failedAttempts);
            f.SetCooldown(_cooldownUntil);
            _forms.Add(f);
        }
    }

    // Displays can appear while locked (dock, monitor wake, display mode
    // change). Keep one form per current screen so nothing goes uncovered.
    private void EnsureCoverage()
    {
        Screen[] screens = Screen.AllScreens;
        bool current = screens.Length == _forms.Count
            && _forms.Zip(screens).All(pair => pair.First.CoverBounds == pair.Second.Bounds);
        if (current)
            return;

        var old = _forms.ToList();
        _forms.Clear();
        BuildForms();
        if (_visible)
        {
            foreach (LockForm f in _forms)
                f.Show();
        }
        foreach (LockForm f in old)
            f.Dispose();
    }

    public void ResetStatus() => SetStatus(DefaultStatus);

    private void ReassertTopmost()
    {
        LockForm? foreground = null;
        foreach (LockForm f in _forms)
        {
            if (f.IsDisposed)
                continue;
            NativeMethods.SetWindowPos(f.Handle, NativeMethods.HWND_TOPMOST, 0, 0, 0, 0,
                NativeMethods.SWP_NOMOVE | NativeMethods.SWP_NOSIZE | NativeMethods.SWP_SHOWWINDOW);
            f.Activate();
            foreground ??= f;
        }
        if (foreground != null)
            NativeMethods.SetForegroundWindow(foreground.Handle);
        ReassertTick?.Invoke();
    }

    public void Dispose()
    {
        _topmostTimer.Dispose();
        foreach (LockForm f in _forms)
            f.Dispose();
        _forms.Clear();
    }
}
