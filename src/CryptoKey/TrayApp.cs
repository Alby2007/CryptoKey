namespace CryptoKey;

/// <summary>
/// System-tray front end for the guard: state-colored icon, dark context menu
/// with glyphs, balloon tips on transitions. Quit only while unlocked.
/// </summary>
internal sealed class TrayApp : IDisposable
{
    private static readonly int[] PauseChoices = { 5, 15, 60 };

    private readonly GuardService _service;
    private readonly KeyConfig _config;
    private readonly TrayIcons _icons;
    private readonly Action<int> _openWindow;
    private readonly NotifyIcon _icon;
    private readonly ContextMenuStrip _menu;
    private readonly ToolStripMenuItem _statusItem;
    private readonly ToolStripMenuItem _keyItem;
    private readonly ToolStripMenuItem _lockItem;
    private readonly ToolStripMenuItem _pauseItem;
    private readonly ToolStripMenuItem _resumeItem;
    private readonly ToolStripMenuItem _quitItem;
    private readonly MessageWindow _msgWin;
    private GuardState? _iconState;

    public TrayApp(GuardService service, KeyConfig config, TrayIcons icons,
        Action<int> openWindow)
    {
        _service = service;
        _config = config;
        _icons = icons;
        _openWindow = openWindow;

        _statusItem = new ToolStripMenuItem("CryptoKey") { Enabled = false };
        _keyItem = new ToolStripMenuItem("") { Enabled = false };
        var openItem = new ToolStripMenuItem("Open CryptoKey")
        { Image = Theme.GlyphBitmap(Glyphs.Home, Theme.Text) };
        openItem.Click += (_, _) => _openWindow(0);
        _lockItem = new ToolStripMenuItem("Lock now")
        { Image = Theme.GlyphBitmap(Glyphs.Lock, Theme.AccentRed) };
        _lockItem.Click += (_, _) => _service.RequestLock();

        _pauseItem = new ToolStripMenuItem("Pause auto-lock")
        { Image = Theme.GlyphBitmap(Glyphs.Pause, Theme.AccentAmber) };
        foreach (int mins in PauseChoices)
        {
            var item = new ToolStripMenuItem($"{mins} minutes");
            int captured = mins;
            item.Click += (_, _) => _service.Pause(captured, out _);
            _pauseItem.DropDownItems.Add(item);
        }

        _resumeItem = new ToolStripMenuItem("Resume")
        { Image = Theme.GlyphBitmap(Glyphs.Play, Theme.AccentGreen) };
        _resumeItem.Click += (_, _) => _service.Resume();

        var settingsItem = new ToolStripMenuItem("Settings…")
        { Image = Theme.GlyphBitmap(Glyphs.Settings, Theme.TextDim) };
        settingsItem.Click += (_, _) => _openWindow(2);

        _quitItem = new ToolStripMenuItem("Quit")
        { Image = Theme.GlyphBitmap(Glyphs.Quit, Theme.TextDim) };
        _quitItem.Click += (_, _) => Application.Exit();

        _menu = new ContextMenuStrip { Renderer = new Theme.DarkMenuRenderer() };
        _menu.Items.AddRange(new ToolStripItem[]
        {
            _statusItem, _keyItem, openItem, new ToolStripSeparator(),
            _lockItem, _pauseItem, _resumeItem, settingsItem,
            new ToolStripSeparator(), _quitItem,
        });
        _menu.Opening += (_, _) => RefreshMenu();

        _icon = new NotifyIcon
        {
            Text = "CryptoKey",
            ContextMenuStrip = _menu,
            Icon = _icons.For(GuardState.Unlocked),
            Visible = true,
        };
        _icon.MouseDoubleClick += (_, _) => _openWindow(0);

        _msgWin = new MessageWindow();
        _msgWin.TaskbarCreated += OnTaskbarCreated;

        _service.StateChanged += OnStateChanged;
        _service.Notification += OnNotification;
        ApplySnapshot(_service.Snapshot());
    }

    private void OnNotification(string title, string body)
    {
        if (_config.Guard.BalloonTips)
            _icon.ShowBalloonTip(4000, title, body, ToolTipIcon.Info);
    }

    private void OnStateChanged(StatusSnapshot snap) => ApplySnapshot(snap);

    private void ApplySnapshot(StatusSnapshot snap)
    {
        if (snap.State == _iconState)
            return;
        GuardState? prev = _iconState;
        _iconState = snap.State;

        _icon.Icon = _icons.For(snap.State);
        _icon.Text = snap.State switch
        {
            GuardState.Locked => "CryptoKey — LOCKED",
            GuardState.Paused => $"CryptoKey — paused until {snap.PausedUntil:HH:mm}",
            _ => "CryptoKey — unlocked",
        };

        if (prev == null || !_config.Guard.BalloonTips)
            return;
        switch (snap.State)
        {
            case GuardState.Locked:
                _icon.ShowBalloonTip(2500, "CryptoKey", "Locked — key absent or unverified.",
                    ToolTipIcon.Warning);
                break;
            case GuardState.Unlocked:
                _icon.ShowBalloonTip(2000, "CryptoKey", "Unlocked.", ToolTipIcon.Info);
                break;
            case GuardState.Paused:
                _icon.ShowBalloonTip(2000, "CryptoKey",
                    $"Auto-lock paused until {snap.PausedUntil:HH:mm}.", ToolTipIcon.Info);
                break;
        }
    }

    private void RefreshMenu()
    {
        StatusSnapshot s = _service.Snapshot();
        _statusItem.Text = s.State == GuardState.Paused
            ? $"CryptoKey — PAUSED (until {s.PausedUntil:HH:mm})"
            : $"CryptoKey — {s.State.ToString().ToUpperInvariant()}";
        _keyItem.Text = s.KeyPresent
            ? $"Key: {s.Model} — present"
            : $"Key: absent ({_config.DeviceSerial})";

        _lockItem.Enabled = s.State != GuardState.Locked;
        _pauseItem.Enabled = s.State != GuardState.Locked; // can extend a pause
        _resumeItem.Enabled = s.State == GuardState.Paused;
        _quitItem.Enabled = s.State != GuardState.Locked;
    }

    // Explorer restarts drop every tray icon; TaskbarCreated is the
    // "come back" broadcast — toggle visibility to re-register ours.
    private void OnTaskbarCreated()
    {
        _icon.Visible = false;
        _icon.Visible = true;
    }

    public void Dispose()
    {
        _msgWin.DestroyHandle();
        _icon.Visible = false;
        _icon.Dispose();
        _menu.Dispose();
    }

    private sealed class MessageWindow : NativeWindow
    {
        public event Action? TaskbarCreated;
        private readonly uint _msg = NativeMethods.RegisterWindowMessage("TaskbarCreated");

        public MessageWindow() => CreateHandle(new CreateParams());

        protected override void WndProc(ref Message m)
        {
            if (m.Msg == _msg)
                TaskbarCreated?.Invoke();
            base.WndProc(ref m);
        }
    }
}
