using System.Globalization;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Media.Immutable;

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
///
/// Rendering is allocation-free in steady state: every frame-invariant
/// brush/pen is a shared static, per-state-color resources come from a
/// small cache keyed on ARGB, animated alphas ride
/// <see cref="DrawingContext.PushOpacity"/> over opaque resources, and the
/// ridge array is a per-instance scratch. All rendering is UI-thread-only,
/// so the caches need no synchronization.
/// </summary>
internal sealed class KeyVisual : Control
{
    public static readonly StyledProperty<KeyVisualState> StateProperty =
        AvaloniaProperty.Register<KeyVisual, KeyVisualState>(nameof(State));

    public static readonly StyledProperty<double> PauseProgressProperty =
        AvaloniaProperty.Register<KeyVisual, double>(nameof(PauseProgress));

    public static readonly StyledProperty<bool> ShowEngravingProperty =
        AvaloniaProperty.Register<KeyVisual, bool>(nameof(ShowEngraving), true);

    private double _eject;          // current eject position (spring)
    private double _velocity;
    private double _phase;          // breathing, radians
    private double _scan;           // 0..1 sweep position
    private double _jitter;         // current horizontal glitch offset
    private double _glitchClock;    // seconds since last glitch burst
    private readonly Random _rng = new();
    private bool _attached;
    private bool _subscribed;       // Motion.Frame hooked
    private readonly ArtRect[] _ridges = new ArtRect[3];

    // ---- Frame-invariant resources (shared statics — never mutated) ----

    private static readonly IBrush PlugMetal = new LinearGradientBrush
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
    private static readonly Pen PlugEdgePen = new(Palette.Brush(0xFF2A323D), 1);
    private static readonly IBrush ContactBrush = Palette.Brush(0xFF1A1F27);
    private static readonly IBrush HousingBrush = new LinearGradientBrush
    {
        StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
        EndPoint = new RelativePoint(1, 1, RelativeUnit.Relative),
        GradientStops =
        {
            new GradientStop(Palette.C(0xFF1B222C), 0),
            new GradientStop(Palette.C(0xFF0B0F14), 1),
        },
    };
    private static readonly Pen PortPen = new(Palette.Hairline, 1);
    private static readonly IBrush ScrewBrush = Palette.Brush(0xFF2B3440);
    private static readonly IBrush SlotBrush = Palette.Brush(0xFF020304);
    private static readonly IBrush BodyMetal = new LinearGradientBrush
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
    private static readonly Pen BodyEdgePen = new(Palette.Brush(DesignTokens.MetalEdge), 1);
    private static readonly IBrush SheenBrush = new LinearGradientBrush
    {
        StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
        EndPoint = new RelativePoint(1, 0, RelativeUnit.Relative),
        GradientStops =
        {
            new GradientStop(Color.FromArgb(0, 255, 255, 255), 0),
            new GradientStop(Color.FromArgb(22, 255, 255, 255), 0.45),
            new GradientStop(Color.FromArgb(0, 255, 255, 255), 0.7),
            new GradientStop(Color.FromArgb(0, 255, 255, 255), 1),
        },
    };
    private static readonly Pen BevelPen = new(Palette.Brush(0x28FFFFFF), 1);
    private static readonly IBrush RidgeBrush = Palette.Brush(0xFF10151C);
    private static readonly Pen HolePen = new(Palette.Brush(DesignTokens.MetalEdge), 1.5);
    private static readonly IBrush SpecBrush = Palette.Brush(0x8CFFFFFF); // a=140
    private static readonly FormattedText EngraveText = new("CRYPTOKEY",
        CultureInfo.InvariantCulture, FlowDirection.LeftToRight,
        new Typeface(FontFamily.Default, FontStyle.Normal, FontWeight.Bold),
        8.5, Palette.Brush(0x5AFFFFFF)) // a=90
    {
        TextAlignment = TextAlignment.Left,
    };

    /// <summary>Per-state-color render resources — one set per distinct state color.</summary>
    private sealed class StateRes
    {
        public required IBrush Opaque;   // LED core + glow layers via PushOpacity
        public required Pen RingPen;     // slot ring — opacity rides PushOpacity
        public required IBrush ScanBand; // verify sweep — the rect moves, brush is reusable
    }

    private static readonly Dictionary<uint, StateRes> _stateRes = new();

    private static StateRes ResFor(Color c)
    {
        if (_stateRes.TryGetValue(c.ToUInt32(), out StateRes? r))
            return r;
        var opaque = new ImmutableSolidColorBrush(c);
        IBrush band = new LinearGradientBrush
        {
            StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
            EndPoint = new RelativePoint(1, 0, RelativeUnit.Relative),
            GradientStops =
            {
                new GradientStop(Color.FromArgb(0, c.R, c.G, c.B), 0),
                new GradientStop(Color.FromArgb(150, c.R, c.G, c.B), 0.5),
                new GradientStop(Color.FromArgb(0, c.R, c.G, c.B), 1),
            },
        };
        r = new StateRes { Opaque = opaque, RingPen = new Pen(opaque, 2), ScanBand = band };
        _stateRes[c.ToUInt32()] = r;
        return r;
    }

    static KeyVisual()
    {
        AffectsRender<KeyVisual>(StateProperty, PauseProgressProperty, ShowEngravingProperty);
    }

    public KeyVisual()
    {
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
        UpdateTimer();
    }

    /// <summary>Subscribes/unsubscribes the shared frame clock — exact refcount.</summary>
    private void UpdateTimer()
    {
        bool want = _attached && Motion.Enabled;
        if (want && !_subscribed)
        {
            Motion.Frame += Tick;
            _subscribed = true;
        }
        else if (!want && _subscribed)
        {
            Motion.Frame -= Tick;
            _subscribed = false;
        }
        if (!want)
        {
            _eject = TargetEject(State);
            _velocity = _jitter = 0;
            InvalidateVisual();
        }
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

    private static RoundedRect RR(ArtRect r) => new(new Rect(r.X, r.Y, r.W, r.H), r.R);

    /// <summary>
    /// Layered translucent discs over the opaque brush — the alpha moves
    /// into PushOpacity so the brush itself is shared, not rebuilt.
    /// </summary>
    private static void Glow(DrawingContext g, double cx, double cy, double radius,
        IBrush opaque, double strength)
    {
        for (int i = 6; i >= 1; i--)
        {
            double r = radius + i * radius * 0.35;
            double a = strength * (0.10 - i * 0.012);
            if (a <= 0)
                continue;
            using (g.PushOpacity(a))
                g.DrawEllipse(opaque, null, new Point(cx, cy), r, r);
        }
    }

    public override void Render(DrawingContext g)
    {
        double scale = Math.Min(Bounds.Width / KeyArt.Width, Bounds.Height / KeyArt.Height);
        if (scale <= 0)
            return;
        double ox = (Bounds.Width - KeyArt.Width * scale) / 2;
        double oy = (Bounds.Height - KeyArt.Height * scale) / 2;

        StateRes res = ResFor(StateColor);
        double breath = Motion.Enabled ? 0.5 + 0.5 * Math.Sin(_phase) : 0.7;
        KeyArtFrame f = KeyArt.Layout(_eject, _ridges);
        bool dim = State is KeyVisualState.Absent or KeyVisualState.Paused;

        using var _ = g.PushTransform(Matrix.CreateScale(scale, scale) * Matrix.CreateTranslation(ox, oy));

        // Ambient state glow behind the port.
        Glow(g, f.Slot.CenterX, f.Slot.CenterY, 26, res.Opaque, 0.55 + 0.45 * breath);

        using (g.PushTransform(Matrix.CreateTranslation(_jitter, 0)))
        using (g.PushOpacity(State == KeyVisualState.Absent ? 0.45 : 1))
        {
            DrawPlug(g, f);
            DrawPort(g, f, res, breath);
            DrawBody(g, f, res, breath, dim);
        }

        if (State == KeyVisualState.Paused)
            DrawPauseRail(g, f);
    }

    private static void DrawPlug(DrawingContext g, KeyArtFrame f)
    {
        g.DrawRectangle(PlugMetal, PlugEdgePen, RR(f.Plug));
        g.DrawRectangle(ContactBrush, null, RR(f.ContactA));
        g.DrawRectangle(ContactBrush, null, RR(f.ContactB));
    }

    private static void DrawPort(DrawingContext g, KeyArtFrame f, StateRes res, double breath)
    {
        g.DrawRectangle(HousingBrush, PortPen, RR(f.Port));
        // Port screws — tiny machined details.
        g.DrawEllipse(ScrewBrush, null, new Point(f.Port.X + 12, f.Port.Y + 12), 3, 3);
        g.DrawEllipse(ScrewBrush, null, new Point(f.Port.X + 12, f.Port.Bottom - 12), 3, 3);

        // Slot + state ring — alpha rides PushOpacity over the opaque pen.
        g.DrawRectangle(SlotBrush, null, RR(f.Slot));
        var ring = new ArtRect(f.Slot.X - 4, f.Slot.Y - 4, f.Slot.W + 4, f.Slot.H + 8, f.Slot.R + 3);
        using (g.PushOpacity(0.55 + 0.45 * breath))
            g.DrawRectangle(null, res.RingPen, RR(ring));
    }

    private void DrawBody(DrawingContext g, KeyArtFrame f, StateRes res, double breath, bool dim)
    {
        RoundedRect body = RR(f.Body);
        g.DrawRectangle(BodyMetal, BodyEdgePen, body);

        using (g.PushClip(body))
        {
            // Brushed-metal sheen: a soft diagonal highlight band.
            g.DrawRectangle(SheenBrush, null, new Rect(f.Body.X, f.Body.Y, f.Body.W, f.Body.H / 2));

            if (State == KeyVisualState.Verifying)
            {
                double x = f.Body.X - 30 + (f.Body.W + 60) * _scan;
                g.DrawRectangle(res.ScanBand, null, new Rect(x - 18, f.Body.Y, 36, f.Body.H));
            }
        }
        // Top bevel highlight.
        g.DrawLine(BevelPen,
            new Point(f.Body.X + 18, f.Body.Y + 1.5), new Point(f.Body.Right - 18, f.Body.Y + 1.5));

        // Grip ridges.
        foreach (ArtRect r in f.Ridges)
            g.DrawRectangle(RidgeBrush, null, RR(r));

        // Lanyard hole.
        g.DrawEllipse(Palette.Carbon, HolePen, new Point(f.HoleX, f.HoleY), f.HoleR, f.HoleR);

        // Status LED.
        double ledStrength = dim ? 0.55 : 0.6 + 0.4 * breath;
        Glow(g, f.LedX, f.LedY, f.LedR, res.Opaque, ledStrength * 1.6);
        g.DrawEllipse(res.Opaque, null, new Point(f.LedX, f.LedY), f.LedR, f.LedR);
        g.DrawEllipse(SpecBrush, null, new Point(f.LedX - 1.8, f.LedY - 1.8), 1.8, 1.8);

        if (ShowEngraving)
            g.DrawText(EngraveText, new Point(f.LedX + 14, f.LedY - EngraveText.Height / 2));
    }

    private void DrawPauseRail(DrawingContext g, KeyArtFrame f)
    {
        double y = f.Body.Bottom + 14;
        g.DrawRectangle(Palette.Raised, null, new RoundedRect(new Rect(f.Body.X, y, f.Body.W, 4), 2));
        double w = Math.Max(4, f.Body.W * (1 - Math.Clamp(PauseProgress, 0, 1)));
        g.DrawRectangle(Palette.Paused, null, new RoundedRect(new Rect(f.Body.X, y, w, 4), 2));
    }
}
