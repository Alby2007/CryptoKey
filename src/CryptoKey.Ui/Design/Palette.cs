using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Media.Immutable;
using Avalonia.Threading;

namespace CryptoKey.Ui;

/// <summary>
/// Avalonia view of <see cref="DesignTokens"/>: colors, frozen brushes, and
/// the resource dictionary every style resolves through. Tokens stay the one
/// source of truth — nothing here invents a color.
/// </summary>
internal static class Palette
{
    public static Color C(uint argb) => Color.FromUInt32(argb);
    public static Color C(uint argb, byte alpha) => Color.FromArgb(alpha,
        DesignTokens.R(argb), DesignTokens.G(argb), DesignTokens.B(argb));

    public static readonly IImmutableSolidColorBrush Carbon = Brush(DesignTokens.Carbon);
    public static readonly IImmutableSolidColorBrush CarbonDeep = Brush(DesignTokens.CarbonDeep);
    public static readonly IImmutableSolidColorBrush Surface = Brush(DesignTokens.Surface);
    public static readonly IImmutableSolidColorBrush Raised = Brush(DesignTokens.Raised);
    public static readonly IImmutableSolidColorBrush RaisedHigh = Brush(DesignTokens.RaisedHigh);
    public static readonly IImmutableSolidColorBrush Hairline = Brush(DesignTokens.Hairline);
    public static readonly IImmutableSolidColorBrush HairlineHi = Brush(DesignTokens.HairlineHi);
    public static readonly IImmutableSolidColorBrush Text = Brush(DesignTokens.Text);
    public static readonly IImmutableSolidColorBrush TextDim = Brush(DesignTokens.TextDim);
    public static readonly IImmutableSolidColorBrush TextFaint = Brush(DesignTokens.TextFaint);
    public static readonly IImmutableSolidColorBrush Signal = Brush(DesignTokens.Signal);
    public static readonly IImmutableSolidColorBrush Armed = Brush(DesignTokens.Armed);
    public static readonly IImmutableSolidColorBrush Locked = Brush(DesignTokens.Locked);
    public static readonly IImmutableSolidColorBrush Paused = Brush(DesignTokens.Paused);

    public static IImmutableSolidColorBrush Brush(uint argb) => new ImmutableSolidColorBrush(C(argb));
    public static IImmutableSolidColorBrush Brush(uint argb, byte alpha) => new ImmutableSolidColorBrush(C(argb, alpha));

    public static IImmutableSolidColorBrush ForState(GuardState s) => Brush(DesignTokens.ForState(s));

    public static readonly FontFamily Mono =
        new("Cascadia Mono, Cascadia Code, Consolas, Menlo, SF Mono, monospace");

    /// <summary>
    /// Installs the token brushes as resources plus the Fluent accent
    /// overrides, so stock controls (ToggleSwitch, Slider, focus rings)
    /// pick up the brand signal instead of the OS accent.
    /// </summary>
    public static void Install(IResourceDictionary r)
    {
        void Add(string key, uint argb)
        {
            r[$"Color.{key}"] = C(argb);
            r[$"Brush.{key}"] = Brush(argb);
        }
        Add("Carbon", DesignTokens.Carbon);
        Add("CarbonDeep", DesignTokens.CarbonDeep);
        Add("Surface", DesignTokens.Surface);
        Add("Raised", DesignTokens.Raised);
        Add("RaisedHigh", DesignTokens.RaisedHigh);
        Add("Hairline", DesignTokens.Hairline);
        Add("HairlineHi", DesignTokens.HairlineHi);
        Add("Text", DesignTokens.Text);
        Add("TextDim", DesignTokens.TextDim);
        Add("TextFaint", DesignTokens.TextFaint);
        Add("Signal", DesignTokens.Signal);
        Add("SignalDeep", DesignTokens.SignalDeep);
        Add("Armed", DesignTokens.Armed);
        Add("Locked", DesignTokens.Locked);
        Add("Paused", DesignTokens.Paused);
        r["Brush.SignalSoft"] = Brush(DesignTokens.Signal, 0x26);
        r["Brush.LockedSoft"] = Brush(DesignTokens.Locked, 0x22);
        r["Brush.ArmedSoft"] = Brush(DesignTokens.Armed, 0x22);
        r["Brush.PausedSoft"] = Brush(DesignTokens.Paused, 0x22);
        r["Brush.SignalHover"] = Brush(0xFF4FDDF1);
        r["Brush.SignalPressed"] = Brush(0xFF1AB8D1);

        // Fluent derives every accent surface from these keys.
        Color signal = C(DesignTokens.Signal);
        r["SystemAccentColor"] = signal;
        r["SystemAccentColorDark1"] = C(0xFF1AB8D1);
        r["SystemAccentColorDark2"] = C(0xFF1497AD);
        r["SystemAccentColorDark3"] = C(DesignTokens.SignalDeep);
        r["SystemAccentColorLight1"] = C(0xFF4FDDF1);
        r["SystemAccentColorLight2"] = C(0xFF7CE6F5);
        r["SystemAccentColorLight3"] = C(0xFFA9EFF9);

        r["MonoFont"] = Mono;
        r["Radius.Sm"] = new CornerRadius(DesignTokens.RadiusSm);
        r["Radius.Md"] = new CornerRadius(DesignTokens.RadiusMd);
        r["Radius.Lg"] = new CornerRadius(DesignTokens.RadiusLg);
        r["Radius.Xl"] = new CornerRadius(DesignTokens.RadiusXl);
    }
}

/// <summary>
/// Global motion gate: the "Interface animations" setting AND the OS
/// reduced-motion preference must both allow it. Controls read
/// <see cref="Enabled"/> each frame and subscribe to <see cref="Changed"/>.
/// </summary>
internal static class Motion
{
    private static bool _setting = true;
    private static bool _osAllows = true;

    public static bool Enabled => _setting && _osAllows;

    public static event Action? Changed;

    public static void Configure(bool setting, bool osAllows)
    {
        bool before = Enabled;
        _setting = setting;
        _osAllows = osAllows;
        if (before != Enabled)
            Changed?.Invoke();
    }

    public static void SetSetting(bool on) => Configure(on, _osAllows);

    public static TimeSpan Duration(int ms) => Enabled ? TimeSpan.FromMilliseconds(ms) : TimeSpan.Zero;

    private static DispatcherTimer? _frameTimer;
    private static Action? _frame;

    /// <summary>
    /// One shared ~16ms beat for every breathing control — exists only while
    /// subscribers do: the timer starts on the first subscribe and stops when
    /// the last unsubscribes (attach/detach symmetry keeps the refcount exact).
    /// UI-thread only, like every DispatcherTimer.
    /// </summary>
    public static event Action? Frame
    {
        add
        {
            _frame += value;
            _frameTimer ??= Kit.Timer(TimeSpan.FromMilliseconds(16),
                DispatcherPriority.Render, () => _frame?.Invoke());
            _frameTimer.Start();
        }
        remove
        {
            _frame -= value;
            if (_frame == null)
                _frameTimer?.Stop();
        }
    }
}
