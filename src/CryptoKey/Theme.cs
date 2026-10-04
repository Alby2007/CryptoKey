using System.Drawing.Drawing2D;

namespace CryptoKey;

/// <summary>Shared palette, fonts, and paint helpers for the whole app.</summary>
internal static class Theme
{
    public static readonly Color Bg          = Color.FromArgb(0x0A, 0x0E, 0x14);
    public static readonly Color BgDeep      = Color.FromArgb(0x06, 0x09, 0x0E);
    public static readonly Color Panel       = Color.FromArgb(0x12, 0x18, 0x21); // legacy alias
    public static readonly Color Surface     = Color.FromArgb(0x12, 0x18, 0x21);
    public static readonly Color SurfaceHigh = Color.FromArgb(0x1A, 0x22, 0x30);
    public static readonly Color Border      = Color.FromArgb(0x26, 0x2E, 0x3B);
    public static readonly Color Text        = Color.FromArgb(0xE8, 0xED, 0xF5);
    public static readonly Color TextDim     = Color.FromArgb(0x93, 0xA1, 0xB5);
    public static readonly Color AccentRed   = Color.FromArgb(0xFF, 0x3B, 0x4E);
    public static readonly Color AccentGreen = Color.FromArgb(0x00, 0xE6, 0x76);
    public static readonly Color AccentAmber = Color.FromArgb(0xFF, 0xB0, 0x20);

    /// <summary>Interactive accent — follows the user's Windows accent color.</summary>
    public static readonly Color Accent = LoadSystemAccent();

    public const int Radius = 10;
    public const int RadiusSmall = 6;

    private static FontFamily? _uiFamily;
    private static FontFamily? _displayFamily;
    private static FontFamily? _monoFamily;

    public static FontFamily UiFamily      => _uiFamily      ??= TryFamily("Segoe UI Variable Text")    ?? new FontFamily("Segoe UI");
    public static FontFamily DisplayFamily => _displayFamily ??= TryFamily("Segoe UI Variable Display") ?? UiFamily;
    public static FontFamily MonoFamily    => _monoFamily    ??= TryFamily("Cascadia Mono")             ?? new FontFamily("Consolas");

    public static Font UIFont(float size = 9f, FontStyle style = FontStyle.Regular)
        => new(UiFamily, size, style);

    public static Font DisplayFont(float size, FontStyle style = FontStyle.Regular)
        => new(DisplayFamily, size, style);

    public static Font MonoFont(float size = 8.5f)
        => new(MonoFamily, size);

    private static FontFamily? TryFamily(string name)
    {
        try { return new FontFamily(name); }
        catch (Exception) { return null; }
    }

    private static Color LoadSystemAccent()
    {
        try
        {
            object? v = Microsoft.Win32.Registry.GetValue(
                @"HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM", "AccentColor", null);
            if (v is int dword)
            {
                // Registry stores AABBGGRR; Color.FromArgb wants R,G,B bytes.
                return Color.FromArgb(255,
                    dword & 0xFF, (dword >> 8) & 0xFF, (dword >> 16) & 0xFF);
            }
        }
        catch (Exception) { }
        return Color.FromArgb(0x4C, 0xC2, 0xFF);
    }

    // ---- Paint helpers ----

    public static Color WithAlpha(Color c, int alpha)
        => Color.FromArgb(Math.Clamp(alpha, 0, 255), c);

    public static Color Blend(Color a, Color b, float t)
    {
        t = Math.Clamp(t, 0f, 1f);
        return Color.FromArgb(
            (int)(a.A + (b.A - a.A) * t),
            (int)(a.R + (b.R - a.R) * t),
            (int)(a.G + (b.G - a.G) * t),
            (int)(a.B + (b.B - a.B) * t));
    }

    public static GraphicsPath RoundedRect(RectangleF r, float radius)
    {
        var p = new GraphicsPath();
        float d = Math.Min(radius * 2f, Math.Min(r.Width, r.Height));
        if (d <= 0)
        {
            p.AddRectangle(r);
            return p;
        }
        p.AddArc(r.X, r.Y, d, d, 180, 90);
        p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
        p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
        p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
        p.CloseFigure();
        return p;
    }

    /// <summary>Layered alpha rings approximating an outer glow.</summary>
    public static void DrawGlow(Graphics g, float cx, float cy, float radius, Color color, int layers = 5)
    {
        for (int i = layers; i >= 1; i--)
        {
            float r = radius + i * 6f;
            int alpha = 26 - i * 5;
            if (alpha <= 0)
                continue;
            using var pen = new Pen(WithAlpha(color, alpha), 3f);
            g.DrawEllipse(pen, cx - r, cy - r, r * 2f, r * 2f);
        }
    }

    public static void DrawIcon(Graphics g, string glyph, float size, Color color, RectangleF bounds)
    {
        using var font = new Font(Glyphs.Family, size);
        using var brush = new SolidBrush(color);
        var format = new StringFormat
        {
            Alignment = StringAlignment.Center,
            LineAlignment = StringAlignment.Center,
        };
        g.DrawString(glyph, font, brush, bounds, format);
    }

    /// <summary>Renders a glyph to a small bitmap (tray menu images, etc).</summary>
    public static Bitmap GlyphBitmap(string glyph, Color color, int size = 16)
    {
        var bmp = new Bitmap(size, size);
        using var g = Graphics.FromImage(bmp);
        g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.AntiAlias;
        DrawIcon(g, glyph, size * 0.72f, color, new RectangleF(0, 0, size, size));
        return bmp;
    }

    /// <summary>Dark window chrome (DWM title bar) — still used for auxiliary windows.</summary>
    public static void SetDarkTitleBar(IntPtr hwnd)
    {
        int dark = 1;
        if (NativeMethods.DwmSetWindowAttribute(hwnd,
                NativeMethods.DWMWA_USE_IMMERSIVE_DARK_MODE, ref dark, sizeof(int)) != 0)
        {
            NativeMethods.DwmSetWindowAttribute(hwnd,
                NativeMethods.DWMWA_USE_IMMERSIVE_DARK_MODE_OLD, ref dark, sizeof(int));
        }
    }

    // ---- Tray context-menu renderer ----

    internal sealed class DarkColorTable : ProfessionalColorTable
    {
        public override Color MenuStripGradientBegin => Surface;
        public override Color MenuStripGradientEnd => Surface;
        public override Color ToolStripDropDownBackground => Surface;
        public override Color ImageMarginGradientBegin => Surface;
        public override Color ImageMarginGradientMiddle => Surface;
        public override Color ImageMarginGradientEnd => Surface;
        public override Color MenuItemSelected => SurfaceHigh;
        public override Color MenuItemSelectedGradientBegin => SurfaceHigh;
        public override Color MenuItemSelectedGradientEnd => SurfaceHigh;
        public override Color MenuItemBorder => Accent;
        public override Color MenuBorder => Border;
        public override Color SeparatorDark => Border;
        public override Color SeparatorLight => Border;
        public override Color ToolStripBorder => Border;
        public override Color OverflowButtonGradientBegin => Surface;
        public override Color OverflowButtonGradientMiddle => Surface;
        public override Color OverflowButtonGradientEnd => Surface;
    }

    internal sealed class DarkMenuRenderer : ToolStripProfessionalRenderer
    {
        public DarkMenuRenderer() : base(new DarkColorTable()) { }

        protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e)
        {
            e.TextColor = e.Item.Enabled ? Text : TextDim;
            base.OnRenderItemText(e);
        }

        protected override void OnRenderArrow(ToolStripArrowRenderEventArgs e)
        {
            e.ArrowColor = e.Item?.Enabled == false ? TextDim : Text;
            base.OnRenderArrow(e);
        }
    }
}
