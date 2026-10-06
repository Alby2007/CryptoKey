using System.Drawing.Drawing2D;

namespace CryptoKey;

/// <summary>
/// GDI renderer for the shared <see cref="KeyArt"/> geometry — paints the
/// same machined USB key the Avalonia <c>KeyVisual</c> draws, so the lock
/// screens and the dashboard show the identical object. All drawing happens
/// in KeyArt's 320×140 design space under a fit-to-bounds transform.
/// </summary>
internal static class KeyArtRenderer
{
    private static Color C(uint argb) => Color.FromArgb(
        DesignTokens.A(argb), DesignTokens.R(argb), DesignTokens.G(argb), DesignTokens.B(argb));

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

        Matrix saved = g.Transform;
        g.TranslateTransform(ox, oy);
        g.ScaleTransform(scale, scale);

        KeyArtFrame f = KeyArt.Layout(eject);
        double breath = 0.5 + 0.5 * Math.Sin(phase);

        // Ambient state glow bleeding out of the slot.
        Theme.DrawGlow(g, (float)f.Slot.CenterX, (float)f.Slot.CenterY, 26f,
            Theme.WithAlpha(state, (int)(70 * (0.55 + 0.45 * breath))), 6);

        var old = g.SmoothingMode;
        g.SmoothingMode = SmoothingMode.AntiAlias;

        DrawPlug(g, f);
        DrawPort(g, f, state, breath);
        DrawBody(g, f, state, breath, dim);

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

    private static void DrawPlug(Graphics g, KeyArtFrame f)
    {
        using var metal = new LinearGradientBrush(R(f.Plug),
            Color.FromArgb(0xB9, 0xC4, 0xD2), Color.FromArgb(0x4A, 0x55, 0x65),
            LinearGradientMode.Vertical);
        var blend = new ColorBlend(3)
        {
            Positions = new[] { 0f, 0.5f, 1f },
            Colors = new[]
            {
                Color.FromArgb(0xB9, 0xC4, 0xD2),
                Color.FromArgb(0x7C, 0x88, 0x98),
                Color.FromArgb(0x4A, 0x55, 0x65),
            },
        };
        metal.InterpolationColors = blend;
        FillRR(g, f.Plug, metal);
        using var pen = new Pen(Color.FromArgb(0x2A, 0x32, 0x3D), 1f);
        StrokeRR(g, f.Plug, pen);
        using var contact = new SolidBrush(Color.FromArgb(0x1A, 0x1F, 0x27));
        g.FillRectangle(contact, R(f.ContactA));
        g.FillRectangle(contact, R(f.ContactB));
    }

    private static void DrawPort(Graphics g, KeyArtFrame f, Color state, double breath)
    {
        using var housing = new LinearGradientBrush(R(f.Port),
            Color.FromArgb(0x1B, 0x22, 0x2C), Color.FromArgb(0x0B, 0x0F, 0x14),
            LinearGradientMode.ForwardDiagonal);
        FillRR(g, f.Port, housing);
        using var portPen = new Pen(C(DesignTokens.Hairline), 1f);
        StrokeRR(g, f.Port, portPen);

        using var screw = new SolidBrush(Color.FromArgb(0x2B, 0x34, 0x40));
        g.FillEllipse(screw, (float)f.Port.X + 9f, (float)f.Port.Y + 9f, 6f, 6f);
        g.FillEllipse(screw, (float)f.Port.X + 9f, (float)f.Port.Bottom - 15f, 6f, 6f);

        using var slotFill = new SolidBrush(Color.FromArgb(0x02, 0x03, 0x04));
        FillRR(g, f.Slot, slotFill);
        var ring = new ArtRect(f.Slot.X - 4, f.Slot.Y - 4, f.Slot.W + 4, f.Slot.H + 8, f.Slot.R + 3);
        using var ringPen = new Pen(
            Theme.WithAlpha(state, (int)(255 * (0.55 + 0.45 * breath))), 2f);
        StrokeRR(g, ring, ringPen);
    }

    private static void DrawBody(Graphics g, KeyArtFrame f, Color state, double breath, bool dim)
    {
        using var metal = new LinearGradientBrush(R(f.Body),
            C(DesignTokens.MetalHi), C(DesignTokens.MetalLo), LinearGradientMode.Vertical);
        metal.InterpolationColors = new ColorBlend(3)
        {
            Positions = new[] { 0f, 0.55f, 1f },
            Colors = new[] { C(DesignTokens.MetalHi), Color.FromArgb(0x23, 0x2B, 0x37), C(DesignTokens.MetalLo) },
        };
        FillRR(g, f.Body, metal);

        // Brushed sheen across the top half, clipped to the body.
        using (var clip = Theme.RoundedRect(R(f.Body), (float)f.Body.R))
        {
            var oldClip = g.Clip;
            g.SetClip(clip, CombineMode.Intersect);
            using var sheen = new LinearGradientBrush(
                new RectangleF((float)f.Body.X, (float)f.Body.Y, (float)f.Body.W, (float)f.Body.H / 2f),
                // GDI+ rejects a degenerate transparent→transparent ctor —
                // the InterpolationColors below supply the real stops.
                Color.FromArgb(0, 255, 255, 255), Color.FromArgb(1, 255, 255, 255),
                LinearGradientMode.Horizontal);
            sheen.InterpolationColors = new ColorBlend(4)
            {
                Positions = new[] { 0f, 0.45f, 0.7f, 1f },
                Colors = new[]
                {
                    Color.FromArgb(0, 255, 255, 255),
                    Color.FromArgb(22, 255, 255, 255),
                    Color.FromArgb(0, 255, 255, 255),
                    Color.FromArgb(0, 255, 255, 255),
                },
            };
            g.FillRectangle(sheen, (float)f.Body.X, (float)f.Body.Y,
                (float)f.Body.W, (float)f.Body.H / 2f);
            g.Clip = oldClip;
        }

        using var edge = new Pen(C(DesignTokens.MetalEdge), 1f);
        StrokeRR(g, f.Body, edge);

        using var bevel = new Pen(Color.FromArgb(40, 255, 255, 255), 1f);
        g.DrawLine(bevel, (float)f.Body.X + 18f, (float)f.Body.Y + 1.5f,
            (float)f.Body.Right - 18f, (float)f.Body.Y + 1.5f);

        using var ridge = new SolidBrush(Color.FromArgb(0x10, 0x15, 0x1C));
        foreach (ArtRect r in f.Ridges)
            g.FillRectangle(ridge, R(r));

        using var holeFill = new SolidBrush(C(DesignTokens.Carbon));
        g.FillEllipse(holeFill, (float)f.HoleX - (float)f.HoleR, (float)f.HoleY - (float)f.HoleR,
            (float)f.HoleR * 2f, (float)f.HoleR * 2f);
        g.DrawEllipse(edge, (float)f.HoleX - (float)f.HoleR, (float)f.HoleY - (float)f.HoleR,
            (float)f.HoleR * 2f, (float)f.HoleR * 2f);

        double ledStrength = dim ? 0.55 : 0.6 + 0.4 * breath;
        Theme.DrawGlow(g, (float)f.LedX, (float)f.LedY, (float)f.LedR,
            Theme.WithAlpha(state, (int)(90 * ledStrength * 1.6)), 5);
        using var led = new SolidBrush(Theme.WithAlpha(state, dim ? 170 : 255));
        g.FillEllipse(led, (float)f.LedX - (float)f.LedR, (float)f.LedY - (float)f.LedR,
            (float)f.LedR * 2f, (float)f.LedR * 2f);
        using var spec = new SolidBrush(Color.FromArgb(140, 255, 255, 255));
        g.FillEllipse(spec, (float)f.LedX - 3.6f, (float)f.LedY - 3.6f, 3.6f, 3.6f);

        using var engrave = new SolidBrush(Color.FromArgb(90, 255, 255, 255));
        using var font = Theme.DisplayFont(8.5f, FontStyle.Bold);
        g.DrawString("CRYPTOKEY", font, engrave, (float)f.LedX + 14f, (float)f.LedY - 5.5f);
    }
}
