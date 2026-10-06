using Avalonia;
using Avalonia.Animation;
using Avalonia.Controls;
using Avalonia.Controls.Shapes;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform;
using Avalonia.Threading;

namespace CryptoKey.Ui;

/// <summary>
/// The dashboard window: collapsible left sidebar (routes + live status rail),
/// crossfading page host, and a toast layer. Custom client area keeps native
/// caption behavior (Snap Layouts on Windows, traffic lights on macOS).
/// Closing hides to the tray — quitting is a tray/rail action.
/// </summary>
internal sealed class MainWindow : Window
{
    private const double SidebarWide = 236, SidebarNarrow = 76, TitleBarH = 40;

    private readonly PageContext _ctx;
    private readonly Dictionary<Route, Page> _pages = new();
    private readonly Dictionary<Route, Button> _nav = new();
    private readonly List<TextBlock> _navLabels = new();
    private readonly TransitioningContentControl _host;
    private readonly ToastHost _toasts = new();
    private readonly Border _sidebar;
    private readonly ColumnDefinition _sideCol;
    private readonly TextBlock _brandText;
    private readonly StatusRail _rail;
    private bool _narrow;

    public Route Current { get; private set; } = Route.Home;

    public MainWindow(GuardClient client, IUiHost host, Action openOnboarding)
    {
        Title = "CryptoKey";
        Width = 1100;
        Height = 760;
        MinWidth = 860;
        MinHeight = 600;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        ExtendClientAreaToDecorationsHint = true;
        ExtendClientAreaChromeHints = ExtendClientAreaChromeHints.PreferSystemChrome;
        ExtendClientAreaTitleBarHeightHint = TitleBarH;
        try { Icon = new WindowIcon(host.AppIcon()); }
        catch (Exception) { }

        _ctx = new PageContext
        {
            Client = client,
            Host = host,
            Toast = Notify,
            Navigate = Navigate,
            Owner = () => this,
            OpenOnboarding = openOnboarding,
        };

        // ---- Sidebar ----
        bool mac = host.Capabilities.PlatformName == "macOS";
        _brandText = Kit.Txt("CryptoKey", "title");
        _brandText.FontSize = 15;
        var collapse = new Button
        {
            Classes = { "ghost" },
            Padding = new Thickness(6),
            MinHeight = 30,
            Content = new Icon(IconData.PanelLeft, 16),
            HorizontalAlignment = HorizontalAlignment.Right,
        };
        ToolTip.SetTip(collapse, "Collapse sidebar");
        Kit.AutomationName(collapse, "Collapse sidebar");
        collapse.Click += (_, _) => SetNarrow(!_narrow);

        var brandMark = new Border
        {
            Width = 30, Height = 30, CornerRadius = new CornerRadius(9),
            Background = new LinearGradientBrush
            {
                StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
                EndPoint = new RelativePoint(1, 1, RelativeUnit.Relative),
                GradientStops =
                {
                    new GradientStop(Palette.C(DesignTokens.Signal), 0),
                    new GradientStop(Palette.C(DesignTokens.SignalDeep), 1),
                },
            },
            Child = new Icon(IconData.Key, 16) { Foreground = Palette.CarbonDeep,
                HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center },
        };
        var brand = new Grid
        {
            ColumnDefinitions = new ColumnDefinitions("Auto,*,Auto"),
            Margin = new Thickness(18, mac ? TitleBarH : 16, 12, 22),
        };
        brand.Children.Add(brandMark);
        _brandText.Margin = new Thickness(10, 0, 0, 0);
        _brandText.VerticalAlignment = VerticalAlignment.Center;
        Grid.SetColumn(_brandText, 1);
        brand.Children.Add(_brandText);
        Grid.SetColumn(collapse, 2);
        brand.Children.Add(collapse);

        var navTop = new StackPanel { Spacing = 2, Margin = new Thickness(12, 0) };
        foreach (Route r in Routes.Primary)
            navTop.Children.Add(NavButton(r));
        var navBottom = new StackPanel { Spacing = 2, Margin = new Thickness(12, 0, 12, 10) };
        foreach (Route r in Routes.Secondary)
            navBottom.Children.Add(NavButton(r));

        _rail = new StatusRail(client, () => Navigate(Route.Home)) { Margin = new Thickness(12, 0, 12, 14) };

        var side = new DockPanel { LastChildFill = true };
        DockPanel.SetDock(brand, Dock.Top);
        side.Children.Add(brand);
        DockPanel.SetDock(_rail, Dock.Bottom);
        side.Children.Add(_rail);
        DockPanel.SetDock(navBottom, Dock.Bottom);
        side.Children.Add(navBottom);
        side.Children.Add(new ScrollViewer { Content = navTop });

        _sidebar = new Border
        {
            Background = Palette.CarbonDeep,
            BorderBrush = Palette.Hairline,
            BorderThickness = new Thickness(0, 0, 1, 0),
            Child = side,
        };

        // ---- Content ----
        _host = new TransitioningContentControl
        {
            PageTransition = new CrossFade(TimeSpan.FromMilliseconds(160)),
        };
        var dragStrip = new Border
        {
            Height = TitleBarH,
            Background = Brushes.Transparent,
            VerticalAlignment = VerticalAlignment.Top,
        };
        dragStrip.PointerPressed += (_, e) =>
        {
            if (e.GetCurrentPoint(this).Properties.IsLeftButtonPressed)
            {
                if (e.ClickCount == 2)
                    WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
                else
                    BeginMoveDrag(e);
            }
        };
        var content = new Grid
        {
            Background = new LinearGradientBrush
            {
                StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
                EndPoint = new RelativePoint(0, 1, RelativeUnit.Relative),
                GradientStops =
                {
                    new GradientStop(Palette.C(0xFF0A0D12), 0),
                    new GradientStop(Palette.C(DesignTokens.Carbon), 0.4),
                },
            },
        };
        _host.Margin = new Thickness(0, TitleBarH - 8, 0, 0);
        content.Children.Add(new GridTexture());
        content.Children.Add(_host);
        content.Children.Add(dragStrip);
        content.Children.Add(_toasts);

        var root = new Grid();
        _sideCol = new ColumnDefinition(SidebarWide, GridUnitType.Pixel);
        root.ColumnDefinitions.Add(_sideCol);
        root.ColumnDefinitions.Add(new ColumnDefinition(1, GridUnitType.Star));
        root.Children.Add(_sidebar);
        Grid.SetColumn(content, 1);
        root.Children.Add(content);
        Content = root;

        KeyDown += OnKeyDown;
        Navigate(Route.Home);
    }

    private Button NavButton(Route r)
    {
        var label = new TextBlock { Text = Routes.Title(r), VerticalAlignment = VerticalAlignment.Center };
        _navLabels.Add(label);
        var b = new Button
        {
            Classes = { "nav" },
            Content = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                Spacing = 12,
                Children = { new Icon(Routes.Icon(r), 18) { VerticalAlignment = VerticalAlignment.Center }, label },
            },
        };
        ToolTip.SetTip(b, Routes.Title(r));
        Kit.AutomationName(b, Routes.Title(r));
        b.Click += (_, _) => Navigate(r);
        _nav[r] = b;
        return b;
    }

    private void SetNarrow(bool narrow)
    {
        _narrow = narrow;
        _sideCol.Width = new GridLength(narrow ? SidebarNarrow : SidebarWide);
        _brandText.IsVisible = !narrow;
        foreach (TextBlock l in _navLabels)
            l.IsVisible = !narrow;
        _rail.Compact = narrow;
    }

    public void Navigate(Route r)
    {
        Current = r;
        foreach ((Route route, Button b) in _nav)
            b.Classes.Set("active", route == r);
        if (!_pages.TryGetValue(r, out Page? page))
        {
            page = r switch
            {
                Route.Key => new KeyPage(_ctx),
                Route.Vault => new VaultPage(_ctx),
                Route.Protection => new ProtectionPage(_ctx),
                Route.Alerts => new AlertsPage(_ctx),
                Route.Activity => new ActivityPage(_ctx),
                Route.General => new GeneralPage(_ctx),
                Route.About => new AboutPage(_ctx),
                _ => new HomePage(_ctx),
            };
            _pages[r] = page;
        }
        _host.PageTransition = Motion.Enabled ? new CrossFade(TimeSpan.FromMilliseconds(160)) : null;
        _host.Content = page;
    }

    public void Notify(string message, bool isError) => _toasts.Show(message, isError);

    private void OnKeyDown(object? sender, KeyEventArgs e)
    {
        // Ctrl/Cmd+1..8 jumps between pages.
        if ((e.KeyModifiers & (KeyModifiers.Control | KeyModifiers.Meta)) == 0)
            return;
        int idx = e.Key - Key.D1;
        Route[] all = Routes.Primary.Concat(Routes.Secondary).ToArray();
        if (idx >= 0 && idx < all.Length)
        {
            Navigate(all[idx]);
            e.Handled = true;
        }
    }

    protected override void OnClosing(WindowClosingEventArgs e)
    {
        // Close = hide to tray; the guard keeps running.
        if (!e.IsProgrammatic)
        {
            e.Cancel = true;
            Hide();
        }
        base.OnClosing(e);
    }
}

/// <summary>
/// Persistent status rail at the sidebar foot: live LED, state word, key line,
/// and one-tap Lock — the guard's state is never more than a glance away.
/// </summary>
internal sealed class StatusRail : Border
{
    private readonly GuardClient _client;
    private readonly Ellipse _led = new() { Width = 10, Height = 10 };
    private readonly Ellipse _halo = new() { Width = 22, Height = 22, Opacity = 0.35 };
    private readonly TextBlock _state = new() { FontWeight = FontWeight.Black, FontSize = 13, LetterSpacing = 1.2 };
    private readonly TextBlock _key = new() { FontSize = 11.5, TextTrimming = TextTrimming.CharacterEllipsis };
    private readonly Button _lock;
    private readonly StackPanel _text;
    private double _phase;
    private bool _compact;

    public StatusRail(GuardClient client, Action openHome)
    {
        _client = client;
        Classes.Add("well");
        Padding = new Thickness(12);
        CornerRadius = new CornerRadius(14);
        _key.Classes.Add("dim");
        _text = new StackPanel { Spacing = 1, VerticalAlignment = VerticalAlignment.Center, Children = { _state, _key } };
        var ledBox = new Grid { Width = 22, Height = 22, Children = { _halo, _led } };
        _led.HorizontalAlignment = _halo.HorizontalAlignment = HorizontalAlignment.Center;
        _led.VerticalAlignment = _halo.VerticalAlignment = VerticalAlignment.Center;

        _lock = Kit.Btn("Lock now", IconData.Lock, "lock small", () => _client.Lock());
        _lock.HorizontalAlignment = HorizontalAlignment.Stretch;
        _lock.Margin = new Thickness(0, 10, 0, 0);

        var top = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*"), ColumnSpacing = 10 };
        top.Children.Add(ledBox);
        Grid.SetColumn(_text, 1);
        top.Children.Add(_text);
        top.PointerPressed += (_, _) => openHome();
        top.Cursor = new Cursor(StandardCursorType.Hand);

        Child = new StackPanel { Children = { top, _lock } };
    }

    public bool Compact
    {
        get => _compact;
        set
        {
            _compact = value;
            _text.IsVisible = !value;
            Kit.SetLabel(_lock, value ? "" : "Lock now", IconData.Lock);
            Padding = new Thickness(value ? 8 : 12);
        }
    }

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        _client.StateChanged += Apply;
        Apply(_client.Snapshot);
        Motion.Frame += Pulse; // shared ~16ms beat — one clock drives all breathing
    }

    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnDetachedFromVisualTree(e);
        _client.StateChanged -= Apply;
        Motion.Frame -= Pulse;
    }

    private void Pulse()
    {
        // Was a private 40ms timer — on the shared 16ms clock the same rate
        // is 0.08 * 16/40 radians per tick.
        _phase = (_phase + 0.032) % (Math.PI * 2);
        _halo.Opacity = Motion.Enabled ? 0.18 + 0.22 * (0.5 + 0.5 * Math.Sin(_phase)) : 0.3;
    }

    private void Apply(StatusSnapshot s)
    {
        IBrush c = Palette.ForState(s.State);
        _led.Fill = c;
        _halo.Fill = c;
        _state.Foreground = c;
        _state.Text = s.State switch
        {
            GuardState.Locked => "LOCKED",
            GuardState.Paused => "PAUSED",
            _ => "ARMED",
        };
        _key.Text = s.State == GuardState.Paused
            ? $"until {s.PausedUntil:HH:mm}"
            : s.KeyPresent ? s.Model ?? "key present" : "key absent";
        _lock.IsEnabled = s.State != GuardState.Locked;
    }
}

/// <summary>Faint engineering grid behind the content — the "circuit board" texture.</summary>
internal sealed class GridTexture : Control
{
    public GridTexture() => IsHitTestVisible = false;

    public override void Render(DrawingContext g)
    {
        var minor = new Pen(new SolidColorBrush(Color.FromArgb(9, 255, 255, 255)), 1);
        var major = new Pen(new SolidColorBrush(Color.FromArgb(14, 34, 211, 238)), 1);
        double step = 28;
        int i = 0;
        for (double x = 0; x < Bounds.Width; x += step, i++)
            g.DrawLine(i % 4 == 0 ? major : minor, new Point(x + 0.5, 0), new Point(x + 0.5, 260));
        i = 0;
        for (double y = 0; y < 260; y += step, i++)
            g.DrawLine(i % 4 == 0 ? major : minor, new Point(0, y + 0.5), new Point(Bounds.Width, y + 0.5));
        // Fade the grid out downward.
        var fade = new LinearGradientBrush
        {
            StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
            EndPoint = new RelativePoint(0, 1, RelativeUnit.Relative),
            GradientStops =
            {
                new GradientStop(Color.FromArgb(0, 7, 9, 12), 0),
                new GradientStop(Palette.C(DesignTokens.Carbon), 1),
            },
        };
        g.DrawRectangle(fade, null, new Rect(0, 0, Bounds.Width, 262));
    }
}
