using Avalonia;
using Avalonia.Animation;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Controls.Shapes;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;

namespace CryptoKey.Ui;

/// <summary>
/// Small factory vocabulary for building views in code — every page is
/// composed from these, so spacing/typography stay on the design system
/// instead of being hand-sized per control (the old layout bug class).
/// </summary>
internal static class Kit
{
    public static TextBlock Txt(string text, params string[] classes)
    {
        var t = new TextBlock { Text = text };
        foreach (string c in classes)
            t.Classes.Add(c);
        return t;
    }

    public static StackPanel V(double spacing, params Control?[] children)
    {
        var p = new StackPanel { Spacing = spacing };
        foreach (Control? c in children)
            if (c != null)
                p.Children.Add(c);
        return p;
    }

    public static StackPanel H(double spacing, params Control?[] children)
    {
        var p = new StackPanel { Orientation = Orientation.Horizontal, Spacing = spacing };
        foreach (Control? c in children)
            if (c != null)
                p.Children.Add(c);
        return p;
    }

    /// <summary>Icon + label button content (icon optional).</summary>
    public static Control Label(string text, string? icon, double iconSize = 16)
    {
        if (icon == null)
            return new TextBlock { Text = text, VerticalAlignment = VerticalAlignment.Center };
        return new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Spacing = 8,
            Children =
            {
                new Icon(icon, iconSize) { VerticalAlignment = VerticalAlignment.Center },
                new TextBlock { Text = text, VerticalAlignment = VerticalAlignment.Center },
            },
        };
    }

    public static Button Btn(string text, string? icon, string variant, Action? onClick = null)
    {
        var b = new Button { Content = Label(text, icon) };
        if (variant.Length > 0)
            foreach (string c in variant.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                b.Classes.Add(c);
        if (onClick != null)
            b.Click += (_, _) => onClick();
        AutomationName(b, text);
        return b;
    }

    public static void SetLabel(Button b, string text, string? icon)
    {
        b.Content = Label(text, icon);
        AutomationName(b, text);
    }

    public static void AutomationName(Control c, string name)
        => Avalonia.Automation.AutomationProperties.SetName(c, name);

    public static Border Divider() => new Border { Classes = { "divider" } };

    /// <summary>
    /// A STOPPED timer. Never use the DispatcherTimer(interval, priority,
    /// handler) constructor: it starts the timer immediately — which once
    /// fired every hold-to-confirm button the instant the Vault page loaded.
    /// </summary>
    public static DispatcherTimer Timer(TimeSpan interval, DispatcherPriority priority, Action tick)
    {
        var t = new DispatcherTimer(priority) { Interval = interval };
        t.Tick += (_, _) => tick();
        return t;
    }

    /// <summary>Page header: big title + one-line description.</summary>
    public static Control PageHeader(string title, string description)
        => V(6, Txt(title, "h1"), Txt(description, "body", "dim"));

    /// <summary>
    /// A titled card holding setting rows separated by hairlines. Rows can be
    /// any control; <see cref="Row"/> is the standard label-left/control-right.
    /// </summary>
    public static Border Section(string title, string icon, string? description, params Control?[] rows)
    {
        var header = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Spacing = 10,
            Children =
            {
                new Border
                {
                    Width = 32, Height = 32, CornerRadius = new CornerRadius(9),
                    Background = Palette.Brush(DesignTokens.Signal, 0x1E),
                    Child = new Icon(icon, 17) { Foreground = Palette.Signal,
                        HorizontalAlignment = HorizontalAlignment.Center,
                        VerticalAlignment = VerticalAlignment.Center },
                },
                new StackPanel
                {
                    VerticalAlignment = VerticalAlignment.Center,
                    Spacing = 2,
                    Children = { Txt(title, "h2") },
                },
            },
        };
        if (description != null)
            ((StackPanel)header.Children[1]).Children.Add(Txt(description, "caption", "dim"));

        var body = new StackPanel { Spacing = 0, Margin = new Thickness(0, 14, 0, 0) };
        bool first = true;
        foreach (Control? row in rows)
        {
            if (row == null)
                continue;
            if (!first)
                body.Children.Add(Divider());
            body.Children.Add(row);
            first = false;
        }
        return new Border
        {
            Classes = { "card" },
            Child = new StackPanel { Children = { header, body } },
        };
    }

    /// <summary>Standard setting row: title + help on the left, control on the right.</summary>
    public static Grid Row(string title, string? help, Control? control, bool wrapControl = false)
    {
        var grid = new Grid
        {
            ColumnDefinitions = new ColumnDefinitions("*,Auto"),
            Margin = new Thickness(0, 12),
            MinHeight = 40,
        };
        var text = V(3, Txt(title, "title"), help != null ? Txt(help, "caption", "dim") : null);
        text.VerticalAlignment = VerticalAlignment.Center;
        text.Margin = new Thickness(0, 0, 20, 0);
        grid.Children.Add(text);
        if (control != null)
        {
            control.VerticalAlignment = VerticalAlignment.Center;
            if (wrapControl)
            {
                // Wide controls drop below the label instead of squeezing it.
                grid.ColumnDefinitions = new ColumnDefinitions("*");
                grid.RowDefinitions = new RowDefinitions("Auto,Auto");
                control.Margin = new Thickness(0, 10, 0, 0);
                Grid.SetRow(control, 1);
            }
            else
            {
                Grid.SetColumn(control, 1);
            }
            grid.Children.Add(control);
        }
        return grid;
    }

    /// <summary>Disable a row's control with an inline reason when the platform lacks the feature.</summary>
    public static Control Gate(Control row, bool available, string reason)
    {
        if (available)
            return row;
        row.IsEnabled = false;
        row.Opacity = 0.55;
        return V(0, row, Txt(reason, "caption", "faint"));
    }

    /// <summary>
    /// True only when a value change can have come from the user. Sliders
    /// coerce Value when Minimum/Maximum are set and ComboBoxes re-resolve
    /// selection on template/ItemsSource changes — both raise change events
    /// nobody asked for. A persist handler that skips this check once
    /// silently rewrote the vault drive letter.
    /// </summary>
    public static bool UserDriven(Control c)
        => c.IsKeyboardFocusWithin || c is ComboBox { IsDropDownOpen: true };

    public static ToggleSwitch Toggle(bool on, Action<bool> changed)
    {
        var t = new ToggleSwitch { IsChecked = on };
        t.IsCheckedChanged += (_, _) => changed(t.IsChecked == true);
        return t;
    }

    public static IBrush ToneBrush(Tone t) => t switch
    {
        Tone.Ok => Palette.Armed,
        Tone.Warn => Palette.Paused,
        Tone.Danger => Palette.Locked,
        Tone.Signal => Palette.Signal,
        _ => Palette.TextDim,
    };

    public static uint ToneArgb(Tone t) => t switch
    {
        Tone.Ok => DesignTokens.Armed,
        Tone.Warn => DesignTokens.Paused,
        Tone.Danger => DesignTokens.Locked,
        Tone.Signal => DesignTokens.Signal,
        _ => DesignTokens.TextDim,
    };

    /// <summary>Wraps page content in a scroller with a comfortable max width.</summary>
    public static ScrollViewer PageScroll(Control content)
        => new()
        {
            Content = new Border
            {
                Padding = new Thickness(36, 28, 36, 40),
                MaxWidth = 920,
                HorizontalAlignment = HorizontalAlignment.Stretch,
                Child = content,
            },
        };
}

/// <summary>
/// A settings drop-down that ignores the mouse wheel while closed (the wheel
/// scrolls the page instead of silently changing the value under the
/// pointer) and raises <see cref="Committed"/> only when the user closes the
/// list on a new choice — never for programmatic or init-time selection.
/// </summary>
internal sealed class SettingCombo : ComboBox
{
    private object? _openedWith;

    public event Action<object>? Committed;

    protected override Type StyleKeyOverride => typeof(ComboBox);

    public SettingCombo()
    {
        DropDownOpened += (_, _) => _openedWith = SelectedItem;
        DropDownClosed += (_, _) =>
        {
            if (SelectedItem is { } item && !Equals(item, _openedWith))
                Committed?.Invoke(item);
        };
    }

    protected override void OnPointerWheelChanged(PointerWheelEventArgs e)
    {
        if (IsDropDownOpen)
            base.OnPointerWheelChanged(e);
        // Closed: leave it unhandled so it bubbles to the page scroller.
    }
}

/// <summary>Pill status chip: tone dot + label.</summary>
internal sealed class StatusChip : Border
{
    private readonly Ellipse _dot = new() { Width = 7, Height = 7, VerticalAlignment = VerticalAlignment.Center };
    private readonly TextBlock _text = new() { FontSize = 12, FontWeight = FontWeight.Medium, VerticalAlignment = VerticalAlignment.Center };

    public StatusChip()
    {
        CornerRadius = new CornerRadius(12);
        Padding = new Thickness(10, 4, 11, 4);
        BorderThickness = new Thickness(1);
        Child = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 7, Children = { _dot, _text } };
    }

    public StatusChip(Chip chip) : this() => Set(chip.Text, chip.Tone);

    public void Set(string text, Tone tone)
    {
        uint c = Kit.ToneArgb(tone);
        _text.Text = text;
        _text.Foreground = tone == Tone.Neutral ? Palette.TextDim : Palette.Brush(c);
        _dot.Fill = Palette.Brush(c);
        Background = Palette.Brush(c, 0x1A);
        BorderBrush = Palette.Brush(c, 0x40);
    }
}

/// <summary>Segmented control — one active segment, like a hardware selector switch.</summary>
internal sealed class Segmented : Border
{
    private readonly List<Button> _buttons = new();
    private int _selected = -1;

    public event Action<int>? SelectionChanged;

    public Segmented(params string[] labels)
    {
        Background = Palette.Raised;
        BorderBrush = Palette.Hairline;
        BorderThickness = new Thickness(1);
        CornerRadius = new CornerRadius(11);
        Padding = new Thickness(3);
        var grid = new UniformGrid { Rows = 1 };
        for (int i = 0; i < labels.Length; i++)
        {
            int idx = i;
            var b = new Button { Content = labels[i], Classes = { "segment" } };
            b.Click += (_, _) => Select(idx, raise: true);
            _buttons.Add(b);
            grid.Children.Add(b);
        }
        Child = grid;
    }

    public int SelectedIndex
    {
        get => _selected;
        set => Select(value, raise: false);
    }

    private void Select(int index, bool raise)
    {
        if (index == _selected)
            return;
        _selected = index;
        for (int i = 0; i < _buttons.Count; i++)
            _buttons[i].Classes.Set("active", i == index);
        if (raise)
            SelectionChanged?.Invoke(index);
    }
}

/// <summary>
/// Press-and-hold confirm for destructive actions — a fill sweeps the button
/// over <see cref="HoldTime"/>; releasing early cancels. Keyboard users hold
/// Space or Enter the same way, so it stays accessible without a mouse.
/// </summary>
internal sealed class HoldButton : Button
{
    private readonly Border _fill;
    private readonly ContentControl _label = new() { VerticalAlignment = VerticalAlignment.Center, HorizontalAlignment = HorizontalAlignment.Center };
    private readonly DispatcherTimer _timer;
    private DateTime _start;
    private bool _holding;

    public TimeSpan HoldTime { get; set; } = TimeSpan.FromMilliseconds(1400);

    public event Action? Confirmed;

    protected override Type StyleKeyOverride => typeof(Button);

    public HoldButton(string text, string icon, string hint = "Hold to confirm")
    {
        Classes.Add("danger");
        _fill = new Border
        {
            Background = Palette.Brush(DesignTokens.Locked, 0x55),
            HorizontalAlignment = HorizontalAlignment.Left,
            Width = 0,
            CornerRadius = new CornerRadius(8),
            Margin = new Thickness(-14, -8),
        };
        SetText(text, icon);
        Content = new Grid { Children = { _fill, _label } };
        ToolTip.SetTip(this, hint);
        _timer = Kit.Timer(TimeSpan.FromMilliseconds(16), DispatcherPriority.Input, Step);
        Kit.AutomationName(this, $"{text} ({hint.ToLowerInvariant()})");
    }

    public void SetText(string text, string icon) => _label.Content = Kit.Label(text, icon);

    private void Begin()
    {
        if (!IsEnabled || _holding)
            return;
        _holding = true;
        _start = DateTime.UtcNow;
        _timer.Start();
    }

    private void Cancel()
    {
        _holding = false;
        _start = default;
        _timer.Stop();
        _fill.Width = 0;
    }

    private void Step()
    {
        // Destructive confirm: only a hold that is genuinely in progress, on
        // an enabled button, can ever complete. A stray tick confirms nothing.
        if (!_holding || !IsEnabled || _start == default)
        {
            Cancel();
            return;
        }
        double t = (DateTime.UtcNow - _start).TotalMilliseconds / HoldTime.TotalMilliseconds;
        _fill.Width = Math.Max(0, (Bounds.Width + 28) * Math.Clamp(t, 0, 1));
        if (t >= 1 && t < 10)
        {
            Cancel();
            Confirmed?.Invoke();
        }
        else if (t >= 10)
        {
            Cancel(); // a clock jump is not a hold
        }
    }

    protected override void OnPointerPressed(PointerPressedEventArgs e)
    {
        if (e.GetCurrentPoint(this).Properties.IsLeftButtonPressed)
        {
            e.Pointer.Capture(this);
            Begin();
            e.Handled = true;
        }
    }

    protected override void OnPointerReleased(PointerReleasedEventArgs e)
    {
        Cancel();
        e.Pointer.Capture(null);
        e.Handled = true;
    }

    protected override void OnPointerCaptureLost(PointerCaptureLostEventArgs e)
    {
        base.OnPointerCaptureLost(e);
        Cancel();
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        if (e.Key is Key.Space or Key.Enter)
        {
            Begin();
            e.Handled = true;
            return;
        }
        base.OnKeyDown(e);
    }

    protected override void OnKeyUp(KeyEventArgs e)
    {
        if (e.Key is Key.Space or Key.Enter)
        {
            Cancel();
            e.Handled = true;
            return;
        }
        base.OnKeyUp(e);
    }

    protected override void OnLostFocus(Avalonia.Interactivity.RoutedEventArgs e)
    {
        base.OnLostFocus(e);
        Cancel();
    }
}

/// <summary>Circular usage meter with a centered caption.</summary>
internal sealed class UsageRing : Control
{
    public static readonly StyledProperty<double> FractionProperty =
        AvaloniaProperty.Register<UsageRing, double>(nameof(Fraction));

    static UsageRing() => AffectsRender<UsageRing>(FractionProperty);

    public double Fraction
    {
        get => GetValue(FractionProperty);
        set => SetValue(FractionProperty, value);
    }

    public UsageRing()
    {
        Width = Height = 64;
        Transitions = new Transitions
        {
            new DoubleTransition { Property = FractionProperty, Duration = TimeSpan.FromMilliseconds(400) },
        };
    }

    public override void Render(DrawingContext g)
    {
        double r = Math.Min(Bounds.Width, Bounds.Height) / 2 - 4;
        var c = new Point(Bounds.Width / 2, Bounds.Height / 2);
        g.DrawEllipse(null, new Pen(Palette.Raised, 6), c, r, r);
        double f = Math.Clamp(Fraction, 0, 1);
        if (f <= 0)
            return;
        double end = -Math.PI / 2 + f * Math.PI * 2;
        var start = new Point(c.X, c.Y - r);
        var stop = new Point(c.X + r * Math.Cos(end), c.Y + r * Math.Sin(end));
        var geo = new StreamGeometry();
        using (var ctx = geo.Open())
        {
            ctx.BeginFigure(start, false);
            if (f >= 0.999)
            {
                ctx.ArcTo(new Point(c.X, c.Y + r), new Size(r, r), 0, false, SweepDirection.Clockwise);
                ctx.ArcTo(start, new Size(r, r), 0, false, SweepDirection.Clockwise);
            }
            else
            {
                ctx.ArcTo(stop, new Size(r, r), 0, f > 0.5, SweepDirection.Clockwise);
            }
            ctx.EndFigure(false);
        }
        IBrush brush = f > 0.9 ? Palette.Locked : Palette.Signal;
        g.DrawGeometry(null, new Pen(brush, 6, lineCap: PenLineCap.Round), geo);
    }
}

/// <summary>Inline tone banner: icon, message, optional action.</summary>
internal sealed class Banner : Border
{
    private readonly TextBlock _text = new() { TextWrapping = TextWrapping.Wrap, VerticalAlignment = VerticalAlignment.Center };
    private readonly Icon _icon = new() { Size = 18, VerticalAlignment = VerticalAlignment.Top };
    private readonly Grid _grid;

    public Banner()
    {
        CornerRadius = new CornerRadius(12);
        Padding = new Thickness(14, 12);
        BorderThickness = new Thickness(1);
        _grid = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*,Auto"), ColumnSpacing = 12 };
        _grid.Children.Add(_icon);
        Grid.SetColumn(_text, 1);
        _grid.Children.Add(_text);
        Child = _grid;
    }

    public void Set(string message, Tone tone, string? icon = null)
    {
        uint c = Kit.ToneArgb(tone);
        _text.Text = message;
        _text.Foreground = Palette.Text;
        _icon.Data = icon ?? (tone == Tone.Danger || tone == Tone.Warn ? IconData.Warning : IconData.Info);
        _icon.Foreground = Palette.Brush(c);
        Background = Palette.Brush(c, 0x16);
        BorderBrush = Palette.Brush(c, 0x45);
    }

    public void SetAction(Control? action)
    {
        foreach (Control old in _grid.Children.Where(x => Grid.GetColumn(x) == 2).ToList())
            _grid.Children.Remove(old);
        if (action == null)
            return;
        Grid.SetColumn(action, 2);
        action.VerticalAlignment = VerticalAlignment.Center;
        _grid.Children.Add(action);
    }
}

/// <summary>Stacked, auto-dismissing toasts anchored bottom-right of a window.</summary>
internal sealed class ToastHost : StackPanel
{
    public ToastHost()
    {
        Spacing = 8;
        HorizontalAlignment = HorizontalAlignment.Right;
        VerticalAlignment = VerticalAlignment.Bottom;
        Margin = new Thickness(0, 0, 24, 24);
        MaxWidth = 380;
        IsHitTestVisible = true;
    }

    public void Show(string message, bool isError)
    {
        Tone tone = isError ? Tone.Danger : Tone.Signal;
        uint c = Kit.ToneArgb(tone);
        var toast = new Border
        {
            Background = Palette.RaisedHigh,
            BorderBrush = Palette.Brush(c, 0x70),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(12),
            Padding = new Thickness(14, 11),
            BoxShadow = new BoxShadows(new BoxShadow { Blur = 24, OffsetY = 8, Color = Color.FromArgb(120, 0, 0, 0) }),
            Opacity = 0,
            Transitions = new Transitions
            {
                new DoubleTransition { Property = OpacityProperty, Duration = Motion.Duration(DesignTokens.MotionStandard) },
            },
            Child = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                Spacing = 10,
                Children =
                {
                    new Icon(isError ? IconData.CircleAlert : IconData.CircleCheck, 17)
                        { Foreground = Palette.Brush(c), VerticalAlignment = VerticalAlignment.Center },
                    new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap, MaxWidth = 310,
                        VerticalAlignment = VerticalAlignment.Center },
                },
            },
        };
        toast.PointerPressed += (_, _) => Children.Remove(toast);
        Children.Add(toast);
        while (Children.Count > 4)
            Children.RemoveAt(0);
        Dispatcher.UIThread.Post(() => toast.Opacity = 1, DispatcherPriority.Background);
        DispatcherTimer.RunOnce(() =>
        {
            toast.Opacity = 0;
            DispatcherTimer.RunOnce(() => Children.Remove(toast), TimeSpan.FromMilliseconds(300));
        }, TimeSpan.FromMilliseconds(isError ? 5500 : 3500));
    }
}
