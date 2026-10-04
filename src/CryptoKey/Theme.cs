namespace CryptoKey;

/// <summary>Shared dark palette + control styling for tray UI and settings.</summary>
internal static class Theme
{
    public static readonly Color Bg = Color.FromArgb(0x0D, 0x11, 0x17);        // #0D1117
    public static readonly Color Panel = Color.FromArgb(0x16, 0x1B, 0x22);     // #161B22
    public static readonly Color Border = Color.FromArgb(0x30, 0x36, 0x3D);    // #30363D
    public static readonly Color Text = Color.FromArgb(0xE6, 0xED, 0xF3);      // #E6EDF3
    public static readonly Color TextDim = Color.FromArgb(0x8B, 0x94, 0x9E);   // #8B949E
    public static readonly Color AccentRed = Color.FromArgb(0xE5, 0x48, 0x4D); // #E5484D
    public static readonly Color AccentGreen = Color.FromArgb(0x3F, 0xB9, 0x50);
    public static readonly Color AccentAmber = Color.FromArgb(0xD2, 0x99, 0x22);

    public static Font UIFont(float size = 9f, FontStyle style = FontStyle.Regular)
        => new("Segoe UI", size, style);

    /// <summary>Dark window chrome (DWM title bar) + recursive control styling.</summary>
    public static void Apply(Form form)
    {
        form.BackColor = Bg;
        form.ForeColor = Text;
        form.Font = UIFont();
        SetDarkTitleBar(form.Handle);
        StyleTree(form);
    }

    // DWMWA_USE_IMMERSIVE_DARK_MODE: 20 on Win11 22000+, 19 on older builds.
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

    public static void StyleTree(Control root)
    {
        foreach (Control c in root.Controls)
        {
            StyleControl(c);
            if (c.HasChildren)
                StyleTree(c);
        }
    }

    private static void StyleControl(Control c)
    {
        switch (c)
        {
            case Button b:
                StyleButton(b);
                break;
            case TextBox t:
                t.BackColor = Bg;
                t.ForeColor = Text;
                t.BorderStyle = BorderStyle.FixedSingle;
                break;
            case NumericUpDown n:
                n.BackColor = Bg;
                n.ForeColor = Text;
                break;
            case CheckBox cb:
                cb.ForeColor = Text;
                cb.BackColor = Color.Transparent;
                break;
            case Label l:
                l.ForeColor = l.ForeColor == SystemColors.ControlText ? Text : l.ForeColor;
                l.BackColor = Color.Transparent;
                break;
            case Panel p:
                p.BackColor = Panel;
                break;
            case GroupBox g:
                g.ForeColor = Text;
                break;
        }
    }

    public static void StyleButton(Button b, bool accent = false)
    {
        b.FlatStyle = FlatStyle.Flat;
        b.BackColor = Panel;
        b.ForeColor = Text;
        b.FlatAppearance.BorderColor = accent ? AccentGreen : Border;
        b.FlatAppearance.MouseOverBackColor = Color.FromArgb(0x21, 0x26, 0x2D);
        b.FlatAppearance.MouseDownBackColor = Color.FromArgb(0x2D, 0x33, 0x3B);
    }

    public static Panel Card()
        => new() { BackColor = Panel, Padding = new Padding(12) };

    internal sealed class DarkColorTable : ProfessionalColorTable
    {
        public override Color MenuStripGradientBegin => Panel;
        public override Color MenuStripGradientEnd => Panel;
        public override Color ToolStripDropDownBackground => Panel;
        public override Color ImageMarginGradientBegin => Panel;
        public override Color ImageMarginGradientMiddle => Panel;
        public override Color ImageMarginGradientEnd => Panel;
        public override Color MenuItemSelected => Color.FromArgb(0x21, 0x26, 0x2D);
        public override Color MenuItemSelectedGradientBegin => Color.FromArgb(0x21, 0x26, 0x2D);
        public override Color MenuItemSelectedGradientEnd => Color.FromArgb(0x21, 0x26, 0x2D);
        public override Color MenuItemBorder => AccentGreen;
        public override Color MenuBorder => Border;
        public override Color SeparatorDark => Border;
        public override Color SeparatorLight => Border;
        public override Color ToolStripBorder => Border;
        public override Color OverflowButtonGradientBegin => Panel;
        public override Color OverflowButtonGradientMiddle => Panel;
        public override Color OverflowButtonGradientEnd => Panel;
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
