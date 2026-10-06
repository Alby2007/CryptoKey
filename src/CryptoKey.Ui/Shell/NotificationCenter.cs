using Avalonia;
using Avalonia.Animation;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform;
using Avalonia.Threading;

namespace CryptoKey.Ui;

/// <summary>
/// Branded transient notifications (replacing OS balloon tips): small
/// non-activating cards stacked in the screen corner nearest the tray —
/// bottom-right on Windows, top-right on macOS. Never steals focus.
/// </summary>
internal sealed class NotificationCenter
{
    private readonly List<Window> _open = new();
    private readonly bool _top;

    public NotificationCenter(bool anchorTop) => _top = anchorTop;

    public void Show(string title, string body, Tone tone, string icon)
    {
        uint c = Kit.ToneArgb(tone);
        var card = new Border
        {
            Margin = new Thickness(10),
            Background = Palette.Surface,
            BorderBrush = Palette.Brush(c, 0x66),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(14),
            Padding = new Thickness(14, 12),
            BoxShadow = new BoxShadows(new BoxShadow { Blur = 20, OffsetY = 6, Color = Color.FromArgb(140, 0, 0, 0) }),
            Child = new Grid
            {
                ColumnDefinitions = new ColumnDefinitions("Auto,*"),
                ColumnSpacing = 12,
                Children =
                {
                    new Border
                    {
                        Width = 34, Height = 34, CornerRadius = new CornerRadius(10),
                        Background = Palette.Brush(c, 0x22),
                        VerticalAlignment = VerticalAlignment.Top,
                        Child = new Icon(icon, 18) { Foreground = Palette.Brush(c),
                            HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center },
                    },
                    Col1(Kit.V(2, Kit.Txt(title, "title"), Kit.Txt(body, "caption", "dim"))),
                },
            },
        };
        var win = new Window
        {
            SystemDecorations = SystemDecorations.None,
            Topmost = true,
            ShowInTaskbar = false,
            ShowActivated = false,
            CanResize = false,
            Width = 360,
            SizeToContent = SizeToContent.Height,
            Background = Brushes.Transparent,
            TransparencyLevelHint = new[] { WindowTransparencyLevel.Transparent },
            WindowStartupLocation = WindowStartupLocation.Manual,
            Content = card,
            Opacity = 0,
            Transitions = new Transitions
            {
                new DoubleTransition { Property = Visual.OpacityProperty, Duration = Motion.Duration(DesignTokens.MotionStandard) },
            },
        };
        win.PointerPressed += (_, _) => win.Close();
        win.Closed += (_, _) =>
        {
            _open.Remove(win);
            Restack();
        };
        _open.Add(win);
        while (_open.Count > 3)
            _open[0].Close();
        win.Show();
        Dispatcher.UIThread.Post(() =>
        {
            Restack();
            win.Opacity = 1;
        }, DispatcherPriority.Render);
        DispatcherTimer.RunOnce(() =>
        {
            win.Opacity = 0;
            DispatcherTimer.RunOnce(() => { if (win.IsVisible) win.Close(); }, TimeSpan.FromMilliseconds(300));
        }, TimeSpan.FromSeconds(4.5));
    }

    private static Control Col1(Control c)
    {
        Grid.SetColumn(c, 1);
        return c;
    }

    private void Restack()
    {
        Screen? screen = _open.FirstOrDefault()?.Screens.Primary;
        if (screen == null)
            return;
        PixelRect wa = screen.WorkingArea;
        double scale = screen.Scaling;
        int offset = 0;
        for (int i = _open.Count - 1; i >= 0; i--)
        {
            Window w = _open[i];
            int pw = (int)(w.Bounds.Width * scale), ph = (int)(w.Bounds.Height * scale);
            int x = wa.Right - pw - 4;
            int y = _top ? wa.Y + 4 + offset : wa.Bottom - ph - 4 - offset;
            w.Position = new PixelPoint(x, y);
            offset += ph;
        }
    }
}
