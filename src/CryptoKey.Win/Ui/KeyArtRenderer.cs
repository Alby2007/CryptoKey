using System.Drawing.Drawing2D;

namespace CryptoKey;

/// <summary>
/// GDI renderer for the shared <see cref="KeyArt"/> geometry — paints the
/// same machined USB key the Avalonia <c>KeyVisual</c> draws, so the lock
/// screens and the dashboard show the identical object. All drawing happens
/// in KeyArt's 320×140 design space under a fit-to-bounds transform.
///
/// No per-frame GDI allocations: every gradient sits at its seated-position
/// design rect and moving parts render under a TranslateTransform of the
/// eject offset — pixel-identical to an eject-baked layout for any eject —
/// and breath-driven alphas quantize to 16 steps into bounded pen/brush
/// caches. The classic surface paints on the engine thread and the secure
/// surface on its lock thread, so all caches are [ThreadStatic]; the cached
/// objects are intentionally never disposed (a handful of handles for
/// process life).
/// </summary>
internal static class KeyArtRenderer
{
    private static Color C(uint argb) => Color.FromArgb(
        DesignTokens.A(argb), DesignTokens.R(argb), DesignTokens.G(argb), DesignTokens.B(argb));

    [ThreadStatic] private static Res? _res;
    [ThreadStatic] private static ArtRect[]? _ridges;
    private static Res R0 => _res ??= new Res();

    /// <param name="eject">0 = seated, 1 = fully ejected (locked).</param>
    /// <param name="phase">breathing phase in radians; 0 renders mid-glow.</param>
    /// <param name="dim">pause/absent presentation — softer LED, muted body.</param>
    public static void Draw(Graphics g, RectangleF bounds, double eject,
        Color state, float phase, bool dim = false)
    {
        float scale = Math.Min(bounds.Width / (float)KeyArt.Width,
            bounds.Height / (float)KeyArt.Height);
        if (scale <= 0)
            return;
        float ox = bounds.X + (bounds.Width - (float)KeyArt.Width * scale) / 2f;
        float oy = bounds.Y + (bounds.Height - (float)KeyArt.Height * scale) / 2f;

        Res r = R0;
        Matrix saved = g.Transform;
        g.TranslateTransform(ox, oy);
        g.ScaleTransform(scale, scale);

        float dx = (float)(Math.Clamp(eject, 0, 1.2) * KeyArt.EjectTravel);
        KeyArtFrame f = KeyArt.Layout(0, _ridges ??= new ArtRect[3]);
        double breath = 0.5 + 0.5 * Math.Sin(phase);

        // Ambient state glow bleeding out of the slot. (DrawGlow's own layer
        // alphas are fixed — the caller's alpha is cosmetic; pass the raw state.)
        Theme.DrawGlow(g, (float)f.Slot.CenterX, (float)f.Slot.CenterY, 26f, state, 6);

        var old = g.SmoothingMode;
        g.SmoothingMode = SmoothingMode.AntiAlias;

        DrawPort(g, f, r, state, breath);

        g.TranslateTransform(dx, 0); // plug + body ride the eject offset
        DrawPlug(g, f, r);
        DrawBody(g, f, r, state, breath, dim);

        g.SmoothingMode = old;
        g.Transform = saved;
    }

    private static RectangleF R(ArtRect r) => new((float)r.X, (float)r.Y, (float)r.W, (float)r.H);

    private static void FillRR(Graphics g, ArtRect r, Brush brush)
    {
        using var path = Theme.RoundedRect(R(r), (float)r.R);
        g.FillPath(brush, path);
    }

    private static void StrokeRR(Graphics g, ArtRect r, Pen pen)
    {
        using var path = Theme.RoundedRect(R(r), (float)r.R);
        g.DrawPath(pen, path);
    }

    /// <summary>Breath alpha quantized to 16 steps — keyed with the color's RGB.</summary>
    private static Pen BreathPen(Res r, Color c, double alpha01, float width)
    {
        int step = (int)Math.Round(Math.Clamp(alpha01, 0, 1) * 15); // 0..15 → *17 = 0..255
        var key = (c.ToArgb() & 0xFFFFFF, step, width);
        if (!r.Pens.TryGetValue(key, out Pen? pen))
            r.Pens[key] = pen = new Pen(Color.FromArgb(step * 17, c), width);
        return pen;
    }

    /// <summary>Solid brush by full ARGB — callers here already pass discrete alphas.</summary>
    private static SolidBrush Solid(Res r, Color c)
    {
        int argb = c.ToArgb();
        if (!r.Brushes.TryGetValue(argb, out SolidBrush? b))
            r.Brushes[argb] = b = new SolidBrush(c);
        return b;
    }

    private static void DrawPlug(Graphics g, KeyArtFrame f, Res r)
    {
        FillRR(g, f.Plug, r.PlugMetal);
        StrokeRR(g, f.Plug, r.PlugEdge);
        g.FillRectangle(r.Contact, R(f.ContactA));
        g.FillRectangle(r.Contact, R(f.ContactB));
    }

    private static void DrawPort(Graphics g, KeyArtFrame f, Res r, Color state, double breath)
    {
        FillRR(g, f.Port, r.Housing);
        StrokeRR(g, f.Port, r.PortPen);

        g.FillEllipse(r.Screw, (float)f.Port.X + 9f, (float)f.Port.Y + 9f, 6f, 6f);
        g.FillEllipse(r.Screw, (float)f.Port.X + 9f, (float)f.Port.Bottom - 15f, 6f, 6f);

        FillRR(g, f.Slot, r.SlotFill);
        var ring = new ArtRect(f.Slot.X - 4, f.Slot.Y - 4, f.Slot.W + 4, f.Slot.H + 8, f.Slot.R + 3);
        StrokeRR(g, ring, BreathPen(r, state, 0.55 + 0.45 * breath, 2f));
    }

    private static void DrawBody(Graphics g, KeyArtFrame f, Res r, Color state, double breath, bool dim)
    {
        FillRR(g, f.Body, r.BodyMetal);

        // Brushed sheen across the top half, clipped to the body.
        using (var clip = Theme.RoundedRect(R(f.Body), (float)f.Body.R))
        {
            var oldClip = g.Clip;
            g.SetClip(clip, CombineMode.Intersect);
            g.FillRectangle(r.Sheen, (float)f.Body.X, (float)f.Body.Y,
                (float)f.Body.W, (float)f.Body.H / 2f);
            g.Clip = oldClip;
        }

        StrokeRR(g, f.Body, r.EdgePen);

        g.DrawLine(r.BevelPen, (float)f.Body.X + 18f, (float)f.Body.Y + 1.5f,
            (float)f.Body.Right - 18f, (float)f.Body.Y + 1.5f);

        foreach (ArtRect rr in f.Ridges)
            g.FillRectangle(r.Ridge, R(rr));

        g.FillEllipse(r.HoleFill, (float)f.HoleX - (float)f.HoleR, (float)f.HoleY - (float)f.HoleR,
            (float)f.HoleR * 2f, (float)f.HoleR * 2f);
        g.DrawEllipse(r.EdgePen, (float)f.HoleX - (float)f.HoleR, (float)f.HoleY - (float)f.HoleR,
            (float)f.HoleR * 2f, (float)f.HoleR * 2f);

        Theme.DrawGlow(g, (float)f.LedX, (float)f.LedY, (float)f.LedR, state, 5);
        g.FillEllipse(Solid(r, Theme.WithAlpha(state, dim ? 170 : 255)),
            (float)f.LedX - (float)f.LedR, (float)f.LedY - (float)f.LedR,
            (float)f.LedR * 2f, (float)f.LedR * 2f);
        g.FillEllipse(r.Spec, (float)f.LedX - 3.6f, (float)f.LedY - 3.6f, 3.6f, 3.6f);

        g.DrawString("CRYPTOKEY", r.EngraveFont, r.Engrave,
            (float)f.LedX + 14f, (float)f.LedY - 5.5f);
    }

    /// <summary>Every frame-invariant GDI object — one bundle per painting thread.</summary>
    private sealed class Res
    {
        public readonly LinearGradientBrush PlugMetal;
        public readonly Pen PlugEdge = new(Color.FromArgb(0x2A, 0x32, 0x3D), 1f);
        public readonly SolidBrush Contact = new(Color.FromArgb(0x1A, 0x1F, 0x27));
        public readonly LinearGradientBrush Housing;
        public readonly Pen PortPen = new(C(DesignTokens.Hairline), 1f);
        public readonly SolidBrush Screw = new(Color.FromArgb(0x2B, 0x34, 0x40));
        public readonly SolidBrush SlotFill = new(Color.FromArgb(0x02, 0x03, 0x04));
        public readonly LinearGradientBrush BodyMetal;
        public readonly Pen EdgePen = new(C(DesignTokens.MetalEdge), 1f);
        public readonly Pen BevelPen = new(Color.FromArgb(40, 255, 255, 255), 1f);
        public readonly SolidBrush Ridge = new(Color.FromArgb(0x10, 0x15, 0x1C));
        public readonly SolidBrush HoleFill = new(C(DesignTokens.Carbon));
        public readonly SolidBrush Spec = new(Color.FromArgb(140, 255, 255, 255));
        public readonly SolidBrush Engrave = new(Color.FromArgb(90, 255, 255, 255));
        public readonly Font EngraveFont = Theme.CachedFont(Theme.DisplayFamily, 8.5f, FontStyle.Bold);
        public readonly LinearGradientBrush Sheen;
        /// <summary>Breath-quantized pens — ≤16 alpha steps per (color, width).</summary>
        public readonly Dictionary<(int rgb, int step, float width), Pen> Pens = new();
        /// <summary>Discrete-alpha brushes keyed by full ARGB.</summary>
        public readonly Dictionary<int, SolidBrush> Brushes = new();

        public Res()
        {
            var f = KeyArt.Layout(0, new ArtRect[3]); // seated rects — the design-space anchors
            PlugMetal = new LinearGradientBrush(R(f.Plug),
                Color.FromArgb(0xB9, 0xC4, 0xD2), Color.FromArgb(0x4A, 0x55, 0x65),
                LinearGradientMode.Vertical)
            {
                InterpolationColors = new ColorBlend(3)
                {
                    Positions = new[] { 0f, 0.5f, 1f },
                    Colors = new[]
                    {
                        Color.FromArgb(0xB9, 0xC4, 0xD2),
                        Color.FromArgb(0x7C, 0x88, 0x98),
                        Color.FromArgb(0x4A, 0x55, 0x65),
                    },
                },
            };
            Housing = new LinearGradientBrush(R(f.Port),
                Color.FromArgb(0x1B, 0x22, 0x2C), Color.FromArgb(0x0B, 0x0F, 0x14),
                LinearGradientMode.ForwardDiagonal);
            BodyMetal = new LinearGradientBrush(R(f.Body),
                C(DesignTokens.MetalHi), C(DesignTokens.MetalLo), LinearGradientMode.Vertical)
            {
                InterpolationColors = new ColorBlend(3)
                {
                    Positions = new[] { 0f, 0.55f, 1f },
                    Colors = new[]
                    {
                        C(DesignTokens.MetalHi), Color.FromArgb(0x23, 0x2B, 0x37), C(DesignTokens.MetalLo),
                    },
                },
            };
            Sheen = new LinearGradientBrush(
                new RectangleF((float)f.Body.X, (float)f.Body.Y, (float)f.Body.W, (float)f.Body.H / 2f),
                // GDI+ rejects a degenerate transparent→transparent ctor —
                // the InterpolationColors supply the real stops.
                Color.FromArgb(0, 255, 255, 255), Color.FromArgb(1, 255, 255, 255),
                LinearGradientMode.Horizontal)
            {
                InterpolationColors = new ColorBlend(4)
                {
                    Positions = new[] { 0f, 0.45f, 0.7f, 1f },
                    Colors = new[]
                    {
                        Color.FromArgb(0, 255, 255, 255),
                        Color.FromArgb(22, 255, 255, 255),
                        Color.FromArgb(0, 255, 255, 255),
                        Color.FromArgb(0, 255, 255, 255),
                    },
                },
            };
        }
    }
}
