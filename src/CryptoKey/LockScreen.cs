namespace CryptoKey;

/// <summary>
/// One borderless topmost black overlay per monitor, with a watchdog timer
/// that re-asserts topmost every 250ms to fight focus stealers.
/// </summary>
internal sealed class LockScreen : IDisposable
{
    private const string DefaultStatus =
        "Insert your CryptoKey, or type the failsafe passphrase and press Enter.";

    private readonly List<LockForm> _forms = new();
    private readonly System.Windows.Forms.Timer _topmostTimer;

    public LockScreen()
    {
        foreach (Screen screen in Screen.AllScreens)
            _forms.Add(new LockForm(screen));

        _topmostTimer = new System.Windows.Forms.Timer { Interval = 250 };
        _topmostTimer.Tick += (_, _) => ReassertTopmost();
    }

    public void Show()
    {
        foreach (LockForm f in _forms)
            f.Show();
        ReassertTopmost();
        _topmostTimer.Start();
    }

    public void Hide()
    {
        _topmostTimer.Stop();
        foreach (LockForm f in _forms)
            f.Hide();
    }

    public void SetPassphraseLength(int len)
    {
        foreach (LockForm f in _forms)
            f.SetPassphraseLength(len);
    }

    public void SetStatus(string message)
    {
        foreach (LockForm f in _forms)
            f.SetStatus(message);
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

        public LockForm(Screen screen)
        {
            FormBorderStyle = FormBorderStyle.None;
            StartPosition = FormStartPosition.Manual;
            BackColor = Color.Black;
            TopMost = true;
            ShowInTaskbar = false;
            Cursor = Cursors.No;

            _title = new Label
            {
                Text = "CRYPTOKEY — LOCKED",
                ForeColor = Color.Red,
                Font = new Font("Consolas", 36f, FontStyle.Bold),
                BackColor = Color.Black,
                AutoSize = true,
            };
            _pass = new Label
            {
                ForeColor = Color.White,
                Font = new Font("Consolas", 24f, FontStyle.Regular),
                BackColor = Color.Black,
                AutoSize = true,
            };
            _status = new Label
            {
                Text = DefaultStatus,
                ForeColor = Color.Gray,
                Font = new Font("Consolas", 12f, FontStyle.Regular),
                BackColor = Color.Black,
                AutoSize = true,
            };
            Controls.AddRange(new Control[] { _title, _pass, _status });
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

        protected override void OnLayout(LayoutEventArgs e)
        {
            base.OnLayout(e);
            CenterLabels();
        }

        private void CenterLabels()
        {
            _title.Left = (ClientSize.Width - _title.Width) / 2;
            _title.Top = (ClientSize.Height / 2) - 120;
            _pass.Left = (ClientSize.Width - _pass.Width) / 2;
            _pass.Top = (ClientSize.Height / 2) - 30;
            _status.Left = (ClientSize.Width - _status.Width) / 2;
            _status.Top = (ClientSize.Height / 2) + 60;
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            e.Cancel = true;
            base.OnFormClosing(e);
        }
    }
}
