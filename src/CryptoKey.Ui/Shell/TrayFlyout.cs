using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform;
using Avalonia.Threading;

namespace CryptoKey.Ui;

/// <summary>
/// Compact quick-control panel anchored at the tray — state at a glance,
/// lock/pause/resume, the vault, and a way into the full app. Dismisses as
/// soon as it loses focus, like the OS's own tray flyouts.
/// </summary>
internal sealed class TrayFlyout : Window
{
    private readonly GuardClient _client;
    private readonly IUiHost _host;
    private readonly Action<Action> _ensureAuth;
    private readonly KeyVisual _key = new() { Height = 92, ShowEngraving = false };
    private readonly TextBlock _word = new() { FontSize = 24, FontWeight = FontWeight.Black, LetterSpacing = 1 };
    private readonly TextBlock _reason = Kit.Txt("", "caption", "dim");
    private readonly Button _lock;
    private readonly Button _resume;
    private readonly StackPanel _pauseRow;
    private readonly Border _vaultRow;
    private readonly StatusChip _vaultChip = new();
    private readonly Button _vaultBtn;
    private DateTime _shownAt;

    public TrayFlyout(GuardClient client, IUiHost host, Action<Route> open,
        Action quit, Action<Action> ensureAuth)
    {
        _client = client;
        _host = host;
        _ensureAuth = ensureAuth;
        SystemDecorations = SystemDecorations.None;
        Topmost = true;
        ShowInTaskbar = false;
        CanResize = false;
        Width = 340;
        SizeToContent = SizeToContent.Height;
        Background = Brushes.Transparent;
        TransparencyLevelHint = new[] { WindowTransparencyLevel.Transparent };
        WindowStartupLocation = WindowStartupLocation.Manual;

        _lock = Kit.Btn("Lock now", IconData.Lock, "lock", () => { _client.Lock(); Hide(); });
        _lock.HorizontalAlignment = HorizontalAlignment.Stretch;
        _resume = Kit.Btn("Resume protection", IconData.Play, "primary",
            () => _ensureAuth(() => _client.Resume()));
        _resume.HorizontalAlignment = HorizontalAlignment.Stretch;

        _pauseRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 6 };
        _pauseRow.Children.Add(new TextBlock { Text = "Pause", VerticalAlignment = VerticalAlignment.Center,
            Foreground = Palette.TextDim, Width = 44 });
        foreach (int mins in new[] { 5, 15, 60 })
        {
            int m = mins;
            _pauseRow.Children.Add(Kit.Btn(m == 60 ? "1 h" : $"{m} min", null, "chip",
                () => _ensureAuth(async () =>
                {
                    string? err = await _client.Pause(m);
                    if (err != null)
                        _reason.Text = err;
                })));
        }

        _vaultBtn = Kit.Btn("Open", IconData.Folder, "small",
            () => _ensureAuth(VaultAction));
        var vaultGrid = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*,Auto"), ColumnSpacing = 10 };
        vaultGrid.Children.Add(new Icon(IconData.Vault, 16) { Foreground = Palette.Signal, VerticalAlignment = VerticalAlignment.Center });
        Grid.SetColumn(_vaultChip, 1);
        _vaultChip.HorizontalAlignment = HorizontalAlignment.Left;
        _vaultChip.VerticalAlignment = VerticalAlignment.Center;
        vaultGrid.Children.Add(_vaultChip);
        Grid.SetColumn(_vaultBtn, 2);
        vaultGrid.Children.Add(_vaultBtn);
        _vaultRow = new Border { Classes = { "well" }, Padding = new Thickness(12, 8), Child = vaultGrid };

        var footer = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto,Auto"), ColumnSpacing = 4 };
        var openBtn = Kit.Btn("Open CryptoKey", IconData.Home, "ghost small", () => { Hide(); open(Route.Home); });
        openBtn.HorizontalAlignment = HorizontalAlignment.Left;
        footer.Children.Add(openBtn);
        var settings = new Button { Classes = { "ghost", "small" }, Content = new Icon(IconData.Settings, 16) };
        ToolTip.SetTip(settings, "Settings");
        Kit.AutomationName(settings, "Settings");
        settings.Click += (_, _) => { Hide(); open(Route.General); };
        Grid.SetColumn(settings, 1);
        footer.Children.Add(settings);
        var quitBtn = new Button { Classes = { "ghost", "small" }, Content = new Icon(IconData.Quit, 16) };
        ToolTip.SetTip(quitBtn, "Quit CryptoKey");
        Kit.AutomationName(quitBtn, "Quit CryptoKey");
        quitBtn.Click += (_, _) => { Hide(); _ensureAuth(quit); };
        Grid.SetColumn(quitBtn, 2);
        footer.Children.Add(quitBtn);

        var head = new Grid { ColumnDefinitions = new ColumnDefinitions("150,*"), ColumnSpacing = 8 };
        head.Children.Add(_key);
        var text = Kit.V(2, Kit.Txt("CRYPTOKEY", "eyebrow"), _word, _reason);
        text.VerticalAlignment = VerticalAlignment.Center;
        Grid.SetColumn(text, 1);
        head.Children.Add(text);

        Content = new Border
        {
            Margin = new Thickness(10),
            Background = Palette.Surface,
            BorderBrush = Palette.HairlineHi,
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(18),
            Padding = new Thickness(16),
            BoxShadow = new BoxShadows(new BoxShadow { Blur = 22, OffsetY = 6, Color = Color.FromArgb(150, 0, 0, 0) }),
            Child = Kit.V(12, head, _lock, _resume, _pauseRow, _vaultRow, Kit.Divider(), footer),
        };

        Deactivated += (_, _) =>
        {
            // The tray click that opened us can deactivate on the way in.
            if ((DateTime.UtcNow - _shownAt).TotalMilliseconds > 300)
                Hide();
        };
        KeyDown += (_, e) =>
        {
            if (e.Key == Avalonia.Input.Key.Escape)
                Hide();
        };
        _client.StateChanged += _ => Apply();
    }

    public void ShowNear()
    {
        Apply();
        _shownAt = DateTime.UtcNow;
        Show();
        Dispatcher.UIThread.Post(Place, DispatcherPriority.Render);
        Activate();
    }

    private void Place()
    {
        (int X, int Y)? cursor = _host.CursorPosition();
        Screen? screen = cursor is (int cx, int cy)
            ? Screens.ScreenFromPoint(new PixelPoint(cx, cy)) ?? Screens.Primary
            : Screens.Primary;
        if (screen == null)
            return;
        PixelRect wa = screen.WorkingArea;
        double scale = screen.Scaling;
        int w = (int)(Bounds.Width * scale), h = (int)(Bounds.Height * scale);
        int x, y;
        if (cursor is (int px, int py))
        {
            x = Math.Clamp(px - w / 2, wa.X + 8, wa.Right - w - 8);
            // Taskbar at the bottom (Windows) → open upward; menu bar on top (macOS) → downward.
            y = py > wa.Y + wa.Height / 2 ? wa.Bottom - h - 8 : wa.Y + 8;
        }
        else
        {
            x = wa.Right - w - 8;
            y = wa.Bottom - h - 8;
        }
        Position = new PixelPoint(x, y);
    }

    private void Apply()
    {
        StatusSnapshot s = _client.Snapshot;
        HomeView v = HomePresenter.Present(s, _client.Settings, _client.DevMode, _host.IsElevated);
        _key.State = v.Visual;
        _word.Text = v.StateWord;
        _word.Foreground = Kit.ToneBrush(v.Accent);
        _reason.Text = v.Reason;
        _lock.IsVisible = v.CanLock;
        _resume.IsVisible = v.CanResume;
        _pauseRow.IsVisible = v.CanPause;
        if (s.Vault is VaultStatus vs)
        {
            _vaultRow.IsVisible = true;
            Chip c = HomePresenter.VaultChip(vs);
            _vaultChip.Set(c.Text, c.Tone);
            _vaultBtn.IsVisible = vs.State is VaultState.Mounted or VaultState.Unsealed;
            Kit.SetLabel(_vaultBtn, vs.State == VaultState.Mounted ? "Open" : "Mount",
                vs.State == VaultState.Mounted ? IconData.Folder : IconData.Play);
        }
        else
        {
            _vaultRow.IsVisible = false;
        }
    }

    private async void VaultAction()
    {
        if (_client.Snapshot.Vault is not VaultStatus vs)
            return;
        if (vs.State == VaultState.Mounted)
        {
            _host.OpenFolder(vs.MountPoint + Path.DirectorySeparatorChar);
            Hide();
        }
        else
        {
            string? err = await _client.Query<string?>((s, _) => s.Vault.TryMount(out string m) ? null : m);
            if (err != null)
                _reason.Text = err;
        }
    }
}
