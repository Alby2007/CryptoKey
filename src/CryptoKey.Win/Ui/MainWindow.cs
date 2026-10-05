namespace CryptoKey;

/// <summary>
/// The app's single window: custom chrome, tab strip, four pages.
/// Closing hides to the tray — Quit stays tray-only while unlocked.
/// </summary>
internal sealed class MainWindow : ChromeForm
{
    private readonly GuardService _service;
    private readonly KeyConfig _config;
    private readonly TrayIcons _icons;
    private readonly bool _devMode;
    private readonly TabStrip _tabs;
    private readonly Panel _host;
    private readonly Toast _toast;
    private readonly Dictionary<int, Control> _pages = new();

    public MainWindow(GuardService service, KeyConfig config, TrayIcons icons, bool devMode)
    {
        _service = service;
        _config = config;
        _icons = icons;
        _devMode = devMode;

        Text = "CryptoKey";
        ClientSize = new Size(760, 680);
        MinimumSize = new Size(620, 560);

        _tabs = new TabStrip { Dock = DockStyle.Top, Height = 46 };
        _tabs.AddTab("Dashboard", Glyphs.Home);
        _tabs.AddTab("Security", Glyphs.Key);
        _tabs.AddTab("Vault", Glyphs.Vault);
        _tabs.AddTab("Settings", Glyphs.Settings);
        _tabs.AddTab("About", Glyphs.Info);
        _tabs.SelectedIndexChanged += (_, _) => ShowPage(_tabs.SelectedIndex);

        _host = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg };
        _toast = new Toast();

        Controls.Add(_host);
        Controls.Add(_tabs);
        Controls.Add(_toast);
        _toast.BringToFront();

        _service.StateChanged += OnStateChanged;
        ApplySnapshot(_service.Snapshot());
        ShowPage(0);
    }

    public void Navigate(int tab)
        => _tabs.SelectedIndex = Math.Clamp(tab, 0, _tabs.Tabs.Count - 1);

    private void ShowPage(int index)
    {
        if (!_pages.TryGetValue(index, out Control? page))
        {
            page = index switch
            {
                1 => new SecurityPage(_config, _service, Notify),
                2 => new VaultPage(_config, _service, Notify),
                3 => new SettingsPage(_config, _service, Notify),
                4 => new AboutPage(),
                _ => new DashboardPage(_service, _config, _devMode),
            };
            page.Dock = DockStyle.Fill;
            _pages[index] = page;
            _host.Controls.Add(page);
        }
        page.BringToFront();
        if (page is DashboardPage dash && _lastSnap != null)
            dash.ApplySnapshot(_lastSnap);
    }

    private StatusSnapshot? _lastSnap;

    private void OnStateChanged(StatusSnapshot snap) => ApplySnapshot(snap);

    private void ApplySnapshot(StatusSnapshot snap)
    {
        _lastSnap = snap;
        Icon = _icons.For(snap.State);
        CaptionDot = StatusHero.ColorFor(snap.State);
        if (_pages.TryGetValue(0, out Control? p) && p is DashboardPage dash)
            dash.ApplySnapshot(snap);
    }

    public void Notify(string message, bool isError)
    {
        _toast.Show(message, isError);
        PositionToast();
    }

    protected override void OnResize(EventArgs e)
    {
        base.OnResize(e);
        PositionToast();
    }

    private void PositionToast()
    {
        if (_toast is { Visible: true })
            _toast.Location = new Point(
                Math.Max(12, Width - _toast.Width - 20),
                Height - _toast.Height - 14);
    }

    // Close = hide to tray. The guard keeps running; quitting lives on the
    // tray menu and only while unlocked.
    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (e.CloseReason is CloseReason.UserClosing or CloseReason.TaskManagerClosing)
        {
            e.Cancel = true;
            Hide();
            return;
        }
        base.OnFormClosing(e);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            _service.StateChanged -= OnStateChanged;
        base.Dispose(disposing);
    }
}
