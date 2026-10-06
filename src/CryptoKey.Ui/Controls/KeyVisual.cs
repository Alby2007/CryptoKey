using System.Globalization;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Threading;

namespace CryptoKey.Ui;

/// <summary>
/// CryptoKey's signature element: a machined USB key that physically
/// reflects the guard's state — seated with a breathing green LED when
/// armed, a cyan scan sweeping the body while verifying, spring-ejected
/// from a red-ringed port when locked, dimmed amber with a countdown rail
/// when paused, glitch-jittering when the key is suspect.
///
/// Geometry comes from <see cref="KeyArt"/> (shared with the GDI lock
/// screen). Animation runs only while attached and motion is enabled; with
/// motion off every value snaps and the art renders statically.
/// </summary>
internal sealed class KeyVisual : Control
{
    public static readonly StyledProperty<KeyVisualState> StateProperty =
        AvaloniaProperty.Register<KeyVisual, KeyVisualState>(nameof(State));

    public static readonly StyledProperty<double> PauseProgressProperty =
        AvaloniaProperty.Register<KeyVisual, double>(nameof(PauseProgress));

    public static readonly StyledProperty<bool> ShowEngravingProperty =
        AvaloniaProperty.Register<KeyVisual, bool>(nameof(ShowEngraving), true);

    private readonly DispatcherTimer _timer;
    private double _eject;          // current eject position (spring)
    private double _velocity;
    private double _phase;          // breathing, radians
    private double _scan;           // 0..1 sweep position
    private double _jitter;         // current horizontal glitch offset
    private double _glitchClock;    // seconds since last glitch burst
    private readonly Random _rng = new();
    private bool _attached;

    static KeyVisual()
    {
        AffectsRender<KeyVisual>(StateProperty, PauseProgressProperty, ShowEngravingProperty);
    }

    public KeyVisual()
    {
        _timer = Kit.Timer(TimeSpan.FromMilliseconds(16), DispatcherPriority.Render, Tick);
        _eject = TargetEject(State);
    }

    public KeyVisualState State
    {
        get => GetValue(StateProperty);
        set => SetValue(StateProperty, value);
    }

    /// <summary>0..1 of the pause elapsed — drives the amber countdown rail.</summary>
    public double PauseProgress
    {
        get => GetValue(PauseProgressProperty);
        set => SetValue(PauseProgressProperty, value);
    }

    public bool ShowEngraving
    {
        get => GetValue(ShowEngravingProperty);
        set => SetValue(ShowEngravingProperty, value);
    }

    private static double TargetEject(KeyVisualState s)
        => s is KeyVisualState.Locked or KeyVisualState.Absent ? 1 : 0;

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property == StateProperty)
        {
            if (!Motion.Enabled)
                _eject = TargetEject(State);
            UpdateTimer();
        }
    }

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        _attached = true;
        Motion.Changed += UpdateTimer;
        UpdateTimer();
    }

    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnDetachedFromVisualTree(e);
        _attached = false;
        Motion.Changed -= UpdateTimer;
        _timer.Stop();
    }

    private void UpdateTimer()
    {
        if (_attached && Motion.Enabled)
        {
            _timer.Start();
            return;
        }
        _timer.Stop();
        _eject = TargetEject(State);
        _velocity = _jitter = 0;
        InvalidateVisual();
    }

    private void Tick()
    {
        const double dt = 0.016;
        // Slightly under-damped spring — the eject overshoots a touch, like a
        // real spring-loaded release.
        double target = TargetEject(State);
        double accel = 260 * (target - _eject) - 20 * _velocity;
        _velocity += accel * dt;
        _eject += _velocity * dt;

        double breathRate = State switch
        {
            KeyVisualState.Locked => 3.2,
            KeyVisualState.Tamper => 5.0,
            KeyVisualState.Paused => 1.4,
            _ => 1.8,
        };
        _phase = (_phase + dt * breathRate) % (Math.PI * 2);
        _scan = (_scan + dt * 0.55) % 1.0;

        if (State == KeyVisualState.Tamper)
        {
            _glitchClock += dt;
            if (_glitchClock > 2.4)
                _glitchClock = 0;
            _jitter = _glitchClock < 0.28 ? (_rng.NextDouble() - 0.5) * 7 : 0;
        }
        else
        {
            _jitter = 0;
        }
        InvalidateVisual();
    }

    private Color StateColor => State switch
    {
        KeyVisualState.Locked or KeyVisualState.Tamper => Palette.C(DesignTokens.Locked),
        KeyVisualState.Paused => Palette.C(DesignTokens.Paused),
        KeyVisualState.Verifying => Palette.C(DesignTokens.Signal),
        KeyVisualState.Absent => Palette.C(DesignTokens.TextFaint),
        _ => Palette.C(DesignTokens.Armed),
    };

    private static IBrush B(Color c, double alpha)
        => new SolidColorBrush(Color.FromArgb((byte)Math.Clamp(alpha * 255, 0, 255), c.R, c.G, c.B));

    private static RoundedRect RR(ArtRect r) => new(new Rect(r.X, r.Y, r.W, r.H), r.R);

    private static void Glow(DrawingContext g, double cx, double cy, double radius, Color c, double strength)
    {
        for (int i = 6; i >= 1; i--)
        {
            double r = radius + i * radius * 0.35;
            double a = strength * (0.10 - i * 0.012);
            if (a <= 0)
                continue;
            g.DrawEllipse(B(c, a), null, new Point(cx, cy), r, r);
        }
    }

    public override void Render(DrawingContext g)
    {
        double scale = Math.Min(Bounds.Width / KeyArt.Width, Bounds.Height / KeyArt.Height);
        if (scale <= 0)
            return;
        double ox = (Bounds.Width - KeyArt.Width * scale) / 2;
        double oy = (Bounds.Height - KeyArt.Height * scale) / 2;

        Color sc = StateColor;
        double breath = Motion.Enabled ? 0.5 + 0.5 * Math.Sin(_phase) : 0.7;
        KeyArtFrame f = KeyArt.Layout(_eject);
        bool dim = State is KeyVisualState.Absent or KeyVisualState.Paused;

        using var _ = g.PushTransform(Matrix.CreateScale(scale, scale) * Matrix.CreateTranslation(ox, oy));

        // Ambient state glow behind the port.
        Glow(g, f.Slot.CenterX, f.Slot.CenterY, 26, sc, 0.55 + 0.45 * breath);

        using (g.PushTransform(Matrix.CreateTranslation(_jitter, 0)))
        using (g.PushOpacity(State == KeyVisualState.Absent ? 0.45 : 1))
        {
            DrawPlug(g, f);
            DrawPort(g, f, sc, breath);
            DrawBody(g, f, sc, breath, dim);
        }

        if (State == KeyVisualState.Paused)
            DrawPauseRail(g, f);
    }

    private static void DrawPlug(DrawingContext g, KeyArtFrame f)
    {
        var metal = new LinearGradientBrush
        {
            StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
            EndPoint = new RelativePoint(0, 1, RelativeUnit.Relative),
            GradientStops =
            {
                new GradientStop(Palette.C(0xFFB9C4D2), 0),
                new GradientStop(Palette.C(0xFF7C8898), 0.5),
                new GradientStop(Palette.C(0xFF4A5565), 1),
            },
        };
        g.DrawRectangle(metal, new Pen(Palette.Brush(0xFF2A323D), 1), RR(f.Plug));
        var contact = Palette.Brush(0xFF1A1F27);
        g.DrawRectangle(contact, null, RR(f.ContactA));
        g.DrawRectangle(contact, null, RR(f.ContactB));
    }

    private static void DrawPort(DrawingContext g, KeyArtFrame f, Color sc, double breath)
    {
        var housing = new LinearGradientBrush
        {
            StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
            EndPoint = new RelativePoint(1, 1, RelativeUnit.Relative),
            GradientStops =
            {
                new GradientStop(Palette.C(0xFF1B222C), 0),
                new GradientStop(Palette.C(0xFF0B0F14), 1),
            },
        };
        g.DrawRectangle(housing, new Pen(Palette.Brush(DesignTokens.Hairline), 1), RR(f.Port));
        // Port screws — tiny machined details.
        var screw = Palette.Brush(0xFF2B3440);
        g.DrawEllipse(screw, null, new Point(f.Port.X + 12, f.Port.Y + 12), 3, 3);
        g.DrawEllipse(screw, null, new Point(f.Port.X + 12, f.Port.Bottom - 12), 3, 3);

        // Slot + state ring.
        var slot = new ArtRect(f.Slot.X, f.Slot.Y, f.Slot.W, f.Slot.H, f.Slot.R);
        g.DrawRectangle(Palette.Brush(0xFF020304), null, RR(slot));
        var ring = new ArtRect(slot.X - 4, slot.Y - 4, slot.W + 4, slot.H + 8, slot.R + 3);
        g.DrawRectangle(null, new Pen(B(sc, 0.55 + 0.45 * breath), 2), RR(ring));
    }

    private void DrawBody(DrawingContext g, KeyArtFrame f, Color sc, double breath, bool dim)
    {
        RoundedRect body = RR(f.Body);
        var metal = new LinearGradientBrush
        {
            StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
            EndPoint = new RelativePoint(0, 1, RelativeUnit.Relative),
            GradientStops =
            {
                new GradientStop(Palette.C(DesignTokens.MetalHi), 0),
                new GradientStop(Palette.C(0xFF232B37), 0.55),
                new GradientStop(Palette.C(DesignTokens.MetalLo), 1),
            },
        };
        g.DrawRectangle(metal, new Pen(Palette.Brush(DesignTokens.MetalEdge), 1), body);

        using (g.PushClip(body))
        {
            // Brushed-metal sheen: a soft diagonal highlight band.
            var sheen = new LinearGradientBrush
            {
                StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
                EndPoint = new RelativePoint(1, 0, RelativeUnit.Relative),
                GradientStops =
                {
                    new GradientStop(Color.FromArgb(0, 255, 255, 255), 0),
                    new GradientStop(Color.FromArgb(22, 255, 255, 255), 0.45),
                    new GradientStop(Color.FromArgb(0, 255, 255, 255), 0.7),
                },
            };
            g.DrawRectangle(sheen, null, new Rect(f.Body.X, f.Body.Y, f.Body.W, f.Body.H / 2));

            if (State == KeyVisualState.Verifying)
            {
                double x = f.Body.X - 30 + (f.Body.W + 60) * _scan;
                var band = new LinearGradientBrush
                {
                    StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
                    EndPoint = new RelativePoint(1, 0, RelativeUnit.Relative),
                    GradientStops =
                    {
                        new GradientStop(Color.FromArgb(0, sc.R, sc.G, sc.B), 0),
                        new GradientStop(Color.FromArgb(150, sc.R, sc.G, sc.B), 0.5),
                        new GradientStop(Color.FromArgb(0, sc.R, sc.G, sc.B), 1),
                    },
                };
                g.DrawRectangle(band, null, new Rect(x - 18, f.Body.Y, 36, f.Body.H));
            }
        }
        // Top bevel highlight.
        g.DrawLine(new Pen(new SolidColorBrush(Color.FromArgb(40, 255, 255, 255)), 1),
            new Point(f.Body.X + 18, f.Body.Y + 1.5), new Point(f.Body.Right - 18, f.Body.Y + 1.5));

        // Grip ridges.
        var ridge = Palette.Brush(0xFF10151C);
        foreach (ArtRect r in f.Ridges)
            g.DrawRectangle(ridge, null, RR(r));

        // Lanyard hole.
        g.DrawEllipse(Palette.Brush(DesignTokens.Carbon), new Pen(Palette.Brush(DesignTokens.MetalEdge), 1.5),
            new Point(f.HoleX, f.HoleY), f.HoleR, f.HoleR);

        // Status LED.
        double ledStrength = dim ? 0.55 : 0.6 + 0.4 * breath;
        Glow(g, f.LedX, f.LedY, f.LedR, sc, ledStrength * 1.6);
        g.DrawEllipse(new SolidColorBrush(sc), null, new Point(f.LedX, f.LedY), f.LedR, f.LedR);
        g.DrawEllipse(new SolidColorBrush(Color.FromArgb(140, 255, 255, 255)), null,
            new Point(f.LedX - 1.8, f.LedY - 1.8), 1.8, 1.8);

        if (ShowEngraving)
        {
            var text = new FormattedText("CRYPTOKEY", CultureInfo.InvariantCulture,
                FlowDirection.LeftToRight, new Typeface(FontFamily.Default, FontStyle.Normal, FontWeight.Bold),
                8.5, new SolidColorBrush(Color.FromArgb(90, 255, 255, 255)))
            {
                TextAlignment = TextAlignment.Left,
            };
            g.DrawText(text, new Point(f.LedX + 14, f.LedY - text.Height / 2));
        }
    }

    private void DrawPauseRail(DrawingContext g, KeyArtFrame f)
    {
        double y = f.Body.Bottom + 14;
        var track = new Rect(f.Body.X, y, f.Body.W, 4);
        g.DrawRectangle(Palette.Brush(DesignTokens.Raised), null, new RoundedRect(track, 2));
        double w = Math.Max(4, f.Body.W * (1 - Math.Clamp(PauseProgress, 0, 1)));
        g.DrawRectangle(Palette.Paused, null, new RoundedRect(new Rect(f.Body.X, y, w, 4), 2));
    }
}
