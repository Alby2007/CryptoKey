using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using CryptoKey.Ui;

namespace CryptoKey;

/// <summary>
/// One shielding window per screen — the visible half of the macOS lock
/// surface. Renders the same design system the dashboard and the Windows
/// lock surface use: the ejected key visual, phrase-length dots (never the
/// characters), status line. All keyboard input still goes through the
/// event tap — this window is output only; it never receives or shows
/// phrase characters.
/// </summary>
internal sealed class LockWindow : Window
{
    internal const string DefaultStatus =
        "Insert your CryptoKey, or type your recovery phrase and press Enter.";

    private const int MaxDotsShown = 30;

    private readonly TextBlock _dots;
    private readonly TextBlock _status;
    private readonly Border _frozen;

    public LockWindow()
    {
        Background = Palette.CarbonDeep;
        Topmost = true;
        SystemDecorations = SystemDecorations.None;
        CanResize = false;
        ShowInTaskbar = false;
        WindowStartupLocation = WindowStartupLocation.Manual;
        Focusable = false; // the event tap owns the keyboard — never take focus

        _dots = new TextBlock
        {
            FontSize = 26,
            Foreground = Palette.Signal,
            TextAlignment = TextAlignment.Center,
            MinHeight = 34,
        };
        _status = new TextBlock
        {
            FontSize = 13,
            Foreground = Palette.TextDim,
            TextAlignment = TextAlignment.Center,
            TextWrapping = TextWrapping.Wrap,
            MaxWidth = 460,
            Text = DefaultStatus,
        };
        _frozen = new Border
        {
            Background = new SolidColorBrush(Color.FromArgb(0x33, 0xFF, 0x3D, 0x57)),
            CornerRadius = new CornerRadius(6),
            Padding = new Thickness(14, 6),
            Margin = new Thickness(0, 0, 0, 10),
            IsVisible = false,
            HorizontalAlignment = HorizontalAlignment.Center,
            Child = new TextBlock
            {
                Text = "INPUT FROZEN — too many attempts",
                FontSize = 12,
                Foreground = Palette.Locked,
            },
        };

        var card = new Border
        {
            Background = Palette.Surface,
            BorderBrush = Palette.Hairline,
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(DesignTokens.RadiusLg),
            Padding = new Thickness(44, 36),
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center,
            Child = new StackPanel
            {
                Spacing = 10,
                Children =
                {
                    new KeyVisual
                    {
                        State = KeyVisualState.Locked,
                        Width = 300,
                        Height = 132,
                    },
                    new TextBlock
                    {
                        Text = "LOCKED",
                        FontSize = DesignTokens.TypeTitle + 2,
                        FontWeight = FontWeight.Bold,
                        Foreground = Palette.Text,
                        TextAlignment = TextAlignment.Center,
                    },
                    _frozen,
                    _dots,
                    _status,
                    new TextBlock
                    {
                        Text = "screen + input captured — macOS",
                        FontSize = DesignTokens.TypeCaption,
                        Foreground = Palette.TextFaint,
                        TextAlignment = TextAlignment.Center,
                        Margin = new Thickness(0, 6, 0, 0),
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
        _status.Foreground = Palette.TextDim;
    }

    public void SetFailed(int count)
    {
        if (count > 0)
            _status.Foreground = Palette.Locked;
    }

    public void SetFrozen(bool frozen)
    {
        _frozen.IsVisible = frozen;
        _dots.IsVisible = !frozen;
    }
}
