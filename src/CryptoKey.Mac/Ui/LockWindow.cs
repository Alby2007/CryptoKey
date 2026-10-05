using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;

namespace CryptoKey;

/// <summary>
/// One shielding window per screen — the visible half of the macOS lock
/// surface. Renders the same card the WinForms LockForm draws: brand,
/// phrase-length dots (never the characters), status line. All keyboard
/// input still goes through the event tap — this window is output only;
/// it never receives or shows phrase characters.
/// </summary>
internal sealed class LockWindow : Window
{
    internal const string DefaultStatus =
        "Insert your CryptoKey, or type your recovery phrase and press Enter.";

    private static readonly IBrush BgBrush = new SolidColorBrush(Color.FromRgb(0x0A, 0x0E, 0x14));
    private static readonly IBrush CardBrush = new SolidColorBrush(Color.FromRgb(0x12, 0x18, 0x21));
    private static readonly IBrush FrameBrush = new SolidColorBrush(Color.FromRgb(0x26, 0x2E, 0x3B));
    private static readonly IBrush TextBrush = new SolidColorBrush(Color.FromRgb(0xE8, 0xED, 0xF5));
    private static readonly IBrush DimBrush = new SolidColorBrush(Color.FromRgb(0x93, 0xA1, 0xB5));
    private static readonly IBrush RedBrush = new SolidColorBrush(Color.FromRgb(0xFF, 0x3B, 0x4E));

    private const int MaxDotsShown = 30;

    private readonly TextBlock _dots;
    private readonly TextBlock _status;
    private readonly Border _frozen;

    public LockWindow()
    {
        Background = BgBrush;
        Topmost = true;
        SystemDecorations = SystemDecorations.None;
        CanResize = false;
        ShowInTaskbar = false;
        WindowStartupLocation = WindowStartupLocation.Manual;
        Focusable = false; // the event tap owns the keyboard — never take focus

        _dots = new TextBlock
        {
            FontSize = 26,
            Foreground = TextBrush,
            TextAlignment = TextAlignment.Center,
            MinHeight = 34,
        };
        _status = new TextBlock
        {
            FontSize = 14,
            Foreground = DimBrush,
            TextAlignment = TextAlignment.Center,
            TextWrapping = TextWrapping.Wrap,
            MaxWidth = 460,
            Text = DefaultStatus,
        };
        _frozen = new Border
        {
            Background = new SolidColorBrush(Color.FromArgb(0x33, 0xFF, 0x3B, 0x4E)),
            CornerRadius = new CornerRadius(6),
            Padding = new Thickness(14, 6),
            Margin = new Thickness(0, 0, 0, 10),
            IsVisible = false,
            Child = new TextBlock
            {
                Text = "INPUT FROZEN — too many attempts",
                FontSize = 12,
                Foreground = RedBrush,
            },
        };

        var card = new Border
        {
            Background = CardBrush,
            BorderBrush = FrameBrush,
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(10),
            Padding = new Thickness(44, 32),
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center,
            Child = new StackPanel
            {
                Spacing = 14,
                Children =
                {
                    new TextBlock
                    {
                        Text = "CRYPTOKEY",
                        FontSize = 20,
                        FontWeight = FontWeight.Bold,
                        Foreground = TextBrush,
                        TextAlignment = TextAlignment.Center,
                    },
                    _frozen,
                    _dots,
                    _status,
                    new TextBlock
                    {
                        Text = "screen + input captured — macOS",
                        FontSize = 11,
                        Foreground = DimBrush,
                        TextAlignment = TextAlignment.Center,
                    },
                },
            },
        };
        Content = card;
    }

    /// <summary>Dots = character count only — phrase text never leaves the tap.</summary>
    public void SetDots(int len)
    {
        _dots.Text = len == 0 ? "" :
            len <= MaxDotsShown ? new string('●', len)
                                : new string('●', MaxDotsShown) + $" +{len - MaxDotsShown}";
    }

    public void SetStatusText(string status)
    {
        _status.Text = status.Length > 0 ? status : DefaultStatus;
        _status.Foreground = DimBrush;
    }

    public void SetFailed(int count)
    {
        if (count > 0)
            _status.Foreground = RedBrush;
    }

    public void SetFrozen(bool frozen)
    {
        _frozen.IsVisible = frozen;
        _dots.IsVisible = !frozen;
    }
}
