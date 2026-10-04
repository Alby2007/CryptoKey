namespace CryptoKey;

/// <summary>
/// One borderless topmost black overlay per monitor, with a watchdog timer
/// that re-asserts topmost every 250ms to fight focus stealers.
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
    private string _status = DefaultStatus;
    private int _passLen;
    private int _failedAttempts;

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

    private void BuildForms()
    {
        foreach (Screen screen in Screen.AllScreens)
        {
            var f = new LockForm(screen);
            f.SetStatus(_status);
            f.SetPassphraseLength(_passLen);
            f.SetFailedAttempts(_failedAttempts);
            _forms.Add(f);
        }
    }

    // Displays can appear while locked (dock, monitor wake, display mode
    // change). Keep one form per current screen so nothing goes uncovered.
    private void EnsureCoverage()
    {
        Screen[] screens = Screen.AllScreens;
        bool current = screens.Length == _forms.Count
            && _forms.Zip(screens).All(pair => pair.First.ScreenBounds == pair.Second.Bounds);
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

    private sealed class LockForm : Form
    {
        private readonly Label _title;
        private readonly Label _pass;
        private readonly Label _status;
        private readonly Label _attempts;

        /// <summary>The screen bounds this form was built to cover.</summary>
        public Rectangle ScreenBounds { get; }

        public LockForm(Screen screen)
        {
            FormBorderStyle = FormBorderStyle.None;
            StartPosition = FormStartPosition.Manual;
            BackColor = Theme.Bg;
            TopMost = true;
            ShowInTaskbar = false;
            Cursor = Cursors.No;
            ScreenBounds = screen.Bounds;

            _title = new Label
            {
                Text = "CRYPTOKEY — LOCKED",
                ForeColor = Theme.AccentRed,
                Font = Theme.UIFont(32f, FontStyle.Bold),
                BackColor = Theme.Bg,
                AutoSize = true,
            };
            _pass = new Label
            {
                ForeColor = Theme.Text,
                Font = Theme.UIFont(20f, FontStyle.Regular),
                BackColor = Theme.Bg,
                AutoSize = true,
            };
            _status = new Label
            {
                Text = DefaultStatus,
                ForeColor = Theme.TextDim,
                Font = Theme.UIFont(11f, FontStyle.Regular),
                BackColor = Theme.Bg,
                AutoSize = true,
            };
            _attempts = new Label
            {
                ForeColor = Theme.AccentAmber,
                Font = Theme.UIFont(11f, FontStyle.Regular),
                BackColor = Theme.Bg,
                AutoSize = true,
            };
            Controls.AddRange(new Control[] { _title, _pass, _status, _attempts });
            Bounds = screen.Bounds;
        }

        public void SetPassphraseLength(int len)
        {
            _pass.Text = new string('*', len);
            CenterLabels();
        }

        public void SetStatus(string message)
        {
            _status.Text = message;
            CenterLabels();
        }

        public void SetFailedAttempts(int count)
        {
            _attempts.Text = count > 0 ? $"Failed unlock attempts: {count}" : "";
            CenterLabels();
        }

        protected override void OnLayout(LayoutEventArgs e)
        {
            base.OnLayout(e);
            CenterLabels();
        }

        private void CenterLabels()
        {
            _title.Left = Math.Max(0, (ClientSize.Width - _title.Width) / 2);
            _title.Top = Math.Max(0, (ClientSize.Height / 2) - 120);
            _pass.Left = Math.Max(0, (ClientSize.Width - _pass.Width) / 2);
            _pass.Top = Math.Max(0, (ClientSize.Height / 2) - 30);
            _status.Left = Math.Max(0, (ClientSize.Width - _status.Width) / 2);
            _status.Top = Math.Max(0, (ClientSize.Height / 2) + 60);
            _attempts.Left = Math.Max(0, (ClientSize.Width - _attempts.Width) / 2);
            _attempts.Top = Math.Max(0, (ClientSize.Height / 2) + 92);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _title.Font.Dispose();
                _pass.Font.Dispose();
                _status.Font.Dispose();
                _attempts.Font.Dispose();
            }
            base.Dispose(disposing);
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            // Resist user close and Task Manager "End task" (WM_CLOSE), but
            // never ApplicationExit or WindowsShutDown — canceling those
            // silently aborts Application.Exit() (the panic combo) and can
            // stall Windows logoff.
            if (e.CloseReason is CloseReason.UserClosing or CloseReason.TaskManagerClosing)
                e.Cancel = true;
            base.OnFormClosing(e);
        }
    }
}
