using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;

namespace CryptoKey;

/// <summary>
/// Borderless window with app-drawn chrome. Non-client area is removed via
/// WM_NCCALCSIZE; caption drag, double-click maximize, edge resize, snap,
/// and min/max/close all go through WM_NCHITTEST + non-client mouse messages,
/// so native window behavior (Aero Snap, Snap Layouts, taskbar) is preserved.
/// </summary>
internal class ChromeForm : Form
{
    private const int TitleBarH = 38;
    private const int ButtonW = 46;
    private const int ResizeBorder = 6;

    private enum CapBtn { None, Min, Max, Close }

    private CapBtn _hot = CapBtn.None;
    private CapBtn _pressed = CapBtn.None;
    private bool _trackingNc;
    private int _topInset;
    private Bitmap? _bg;
    private Color? _captionDot;

    /// <summary>Optional state dot rendered beside the title.</summary>
    public Color? CaptionDot
    {
        get => _captionDot;
        set { _captionDot = value; Invalidate(TitleRect()); }
    }

    public ChromeForm()
    {
        FormBorderStyle = FormBorderStyle.None;
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Theme.Bg;
        Font = Theme.UIFont(9f);
        DoubleBuffered = true;
        Padding = new Padding(0, TitleBarH, 0, 0);
        MinimumSize = new Size(560, 480);
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        Theme.SetDarkTitleBar(Handle);
        int round = NativeMethods.DWMWCP_ROUND;
        NativeMethods.DwmSetWindowAttribute(Handle,
            NativeMethods.DWMWA_WINDOW_CORNER_PREFERENCE, ref round, sizeof(int));
    }

    private bool Zoomed => WindowState == FormWindowState.Maximized;

    private void UpdateInsets()
    {
        _topInset = Zoomed ? EdgeInset() : 0;
        int l = Zoomed ? EdgeInset() : 0;
        Padding = new Padding(l, TitleBarH + _topInset, l, l);
    }

    private static int EdgeInset()
        => NativeMethods.GetSystemMetrics(NativeMethods.SM_CXSIZEFRAME)
         + NativeMethods.GetSystemMetrics(NativeMethods.SM_CXPADDEDBORDER);

    private Rectangle TitleRect() => new(0, _topInset, Width, TitleBarH);

    private Rectangle ButtonRect(CapBtn b) => b switch
    {
        CapBtn.Close => new Rectangle(Width - ButtonW, _topInset, ButtonW, TitleBarH),
        CapBtn.Max => new Rectangle(Width - ButtonW * 2, _topInset, ButtonW, TitleBarH),
        CapBtn.Min => new Rectangle(Width - ButtonW * 3, _topInset, ButtonW, TitleBarH),
        _ => Rectangle.Empty,
    };

    private CapBtn ButtonAt(Point p)
    {
        foreach (CapBtn b in new[] { CapBtn.Close, CapBtn.Max, CapBtn.Min })
            if (ButtonRect(b).Contains(p))
                return b;
        return CapBtn.None;
    }

    // ---- WndProc: chrome plumbing ----

    protected override void WndProc(ref Message m)
    {
        switch (m.Msg)
        {
            case 0x0083: // WM_NCCALCSIZE — swallow the frame; client = whole window
                if (m.WParam != IntPtr.Zero)
                {
                    m.Result = IntPtr.Zero;
                    return;
                }
                break;

            case 0x0084: // WM_NCHITTEST
                m.Result = (IntPtr)HitTest(m.LParam);
                return;

            case 0x0024: // WM_GETMINMAXINFO — honor the work area when maximized
                base.WndProc(ref m);   // let defaults fill in, then override
                WmGetMinMaxInfo(m.LParam);
                return;

            case 0x00A0: // WM_NCMOUSEMOVE
                OnNcMouseMove(PointToClient(LParamPoint(m.LParam)));
                return;

            case 0x02A2: // WM_NCMOUSELEAVE
                SetHot(CapBtn.None);
                _trackingNc = false;
                return;

            case 0x00A1: // WM_NCLBUTTONDOWN — consume only on our buttons;
                {        // caption clicks fall through for native drag/dbl-click
                    CapBtn hit = ButtonAt(PointToClient(LParamPoint(m.LParam)));
                    if (hit == CapBtn.None)
                        break;
                    _pressed = hit;
                    Invalidate();
                    return;
                }

            case 0x00A2: // WM_NCLBUTTONUP
                {
                    CapBtn released = ButtonAt(PointToClient(LParamPoint(m.LParam)));
                    if (_pressed == CapBtn.None && released == CapBtn.None)
                        break;
                    CapBtn was = _pressed;
                    _pressed = CapBtn.None;
                    Invalidate();
                    if (released == was && was != CapBtn.None)
                        ActivateButton(was);
                    return;
                }
        }
        base.WndProc(ref m);
    }

    private static Point LParamPoint(IntPtr lParam)
        => new(unchecked((short)(lParam.ToInt64() & 0xFFFF)),
               unchecked((short)((lParam.ToInt64() >> 16) & 0xFFFF)));

    private int HitTest(IntPtr lParam)
    {
        Point p = PointToClient(LParamPoint(lParam));

        if (Zoomed)
        {
            if (p.Y < _topInset)
                return 0; // invisible frame band — nothing
            CapBtn zb = ButtonAt(p);
            if (zb != CapBtn.None)
                return zb == CapBtn.Min ? 8 : zb == CapBtn.Max ? 9 : 20;
            return TitleRect().Contains(p) ? 2 : 1;
        }

        bool left = p.X < ResizeBorder;
        bool right = p.X >= Width - ResizeBorder;
        bool top = p.Y < ResizeBorder;
        bool bottom = p.Y >= Height - ResizeBorder;

        if (left && top) return 13;
        if (right && top) return 14;
        if (left && bottom) return 16;
        if (right && bottom) return 17;
        if (left) return 10;
        if (right) return 11;
        if (top) return 12;
        if (bottom) return 15;

        CapBtn b = ButtonAt(p);
        if (b != CapBtn.None)
            return b == CapBtn.Min ? 8 : b == CapBtn.Max ? 9 : 20; // HTMINBUTTON/HTMAXBUTTON/HTCLOSE
        if (TitleRect().Contains(p))
            return 2; // HTCAPTION — drag + double-click maximize
        return 1;     // HTCLIENT
    }

    private void OnNcMouseMove(Point p)
    {
        SetHot(ButtonAt(p));
        if (!_trackingNc)
        {
            var tme = new NativeMethods.TRACKMOUSEEVENT
            {
                cbSize = Marshal.SizeOf<NativeMethods.TRACKMOUSEEVENT>(),
                dwFlags = NativeMethods.TME_LEAVE | NativeMethods.TME_NONCLIENT,
                hwndTrack = Handle,
            };
            NativeMethods.TrackMouseEvent(ref tme);
            _trackingNc = true;
        }
    }

    private void SetHot(CapBtn b)
    {
        if (b == _hot)
            return;
        _hot = b;
        Invalidate();
    }

    private void ActivateButton(CapBtn b)
    {
        switch (b)
        {
            case CapBtn.Min:
                WindowState = FormWindowState.Minimized;
                break;
            case CapBtn.Max:
                WindowState = Zoomed ? FormWindowState.Normal : FormWindowState.Maximized;
                break;
            case CapBtn.Close:
                Close();
                break;
        }
    }

    private void WmGetMinMaxInfo(IntPtr lParam)
    {
        var mmi = Marshal.PtrToStructure<NativeMethods.MINMAXINFO>(lParam);
        IntPtr mon = NativeMethods.MonitorFromWindow(Handle,
            NativeMethods.MONITOR_DEFAULTTONEAREST);
        var mi = new NativeMethods.MONITORINFO
        { cbSize = Marshal.SizeOf<NativeMethods.MONITORINFO>() };
        if (NativeMethods.GetMonitorInfo(mon, ref mi))
        {
            mmi.ptMaxPosition.X = mi.rcWork.Left - mi.rcMonitor.Left;
            mmi.ptMaxPosition.Y = mi.rcWork.Top - mi.rcMonitor.Top;
            mmi.ptMaxSize.X = mi.rcWork.Right - mi.rcWork.Left;
            mmi.ptMaxSize.Y = mi.rcWork.Bottom - mi.rcWork.Top;
        }
        if (MinimumSize != Size.Empty)
        {
            mmi.ptMinTrackSize.X = MinimumSize.Width;
            mmi.ptMinTrackSize.Y = MinimumSize.Height;
        }
        Marshal.StructureToPtr(mmi, lParam, false);
        // fall through to base — do not return early
    }

    // ---- Painting ----

    protected override void OnResize(EventArgs e)
    {
        base.OnResize(e);
        UpdateInsets();
        RebuildBackground();
    }

    private void RebuildBackground()
    {
        if (Width <= 0 || Height <= 0)
            return;
        _bg?.Dispose();
        _bg = new Bitmap(Width, Height);
        using var g = Graphics.FromImage(_bg);
        using (var grad = new LinearGradientBrush(
            new Rectangle(0, 0, Width, Height), Theme.Bg, Theme.BgDeep,
            LinearGradientMode.Vertical))
            g.FillRectangle(grad, 0, 0, Width, Height);

        // Faint accent radial, top-right — gives the dark a hint of depth.
        using (var glow = new PathGradientBrush(GlowEllipse(Width * 0.88f, -Height * 0.12f, Width * 0.5f)))
        {
            glow.CenterColor = Theme.WithAlpha(Theme.Accent, 14);
            glow.SurroundColors = new[] { Color.Transparent };
            g.FillRectangle(glow, 0, 0, Width, Height);
        }
        using (var glow = new PathGradientBrush(GlowEllipse(-Width * 0.15f, Height * 1.05f, Width * 0.5f)))
        {
            glow.CenterColor = Theme.WithAlpha(Theme.AccentGreen, 10);
            glow.SurroundColors = new[] { Color.Transparent };
            g.FillRectangle(glow, 0, 0, Width, Height);
        }
    }

    private static PointF[] GlowEllipse(float cx, float cy, float r)
    {
        var pts = new PointF[8];
        for (int i = 0; i < 8; i++)
        {
            double a = i * Math.PI / 4.0;
            pts[i] = new PointF(cx + (float)(Math.Cos(a) * r), cy + (float)(Math.Sin(a) * r));
        }
        return pts;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        Graphics g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;

        if (_bg != null)
            g.DrawImageUnscaled(_bg, 0, 0);
        else
            g.Clear(Theme.Bg);

        Rectangle title = TitleRect();

        // Title strip divider.
        using (var pen = new Pen(Theme.WithAlpha(Theme.Border, 140), 1f))
            g.DrawLine(pen, 0, title.Bottom - 0.5f, Width, title.Bottom - 0.5f);

        // App glyph + name.
        float x = 14f;
        Theme.DrawIcon(g, Glyphs.Lock, 11f, Theme.AccentGreen,
            new RectangleF(x - 4f, title.Top, 22f, title.Height));
        x += 20f;
        using (var titleFont = Theme.UIFont(9.5f, FontStyle.Bold))
        using (var brush = new SolidBrush(Theme.Text))
        {
            var fmt = new StringFormat { LineAlignment = StringAlignment.Center };
            g.DrawString("CryptoKey", titleFont, brush,
                new RectangleF(x, title.Top, 120f, title.Height), fmt);
        }
        x += 66f;
        if (_captionDot is Color dot)
        {
            using var brush = new SolidBrush(dot);
            float d = 8f;
            g.FillEllipse(brush, x, title.Top + title.Height / 2f - d / 2f, d, d);
        }

        // Caption buttons.
        PaintCaptionButton(g, CapBtn.Min, Glyphs.Minimize);
        PaintCaptionButton(g, CapBtn.Max, Zoomed ? Glyphs.Restore : Glyphs.Maximize);
        PaintCaptionButton(g, CapBtn.Close, Glyphs.Close);
    }

    private void PaintCaptionButton(Graphics g, CapBtn b, string glyph)
    {
        Rectangle r = ButtonRect(b);
        if (_hot == b || _pressed == b)
        {
            Color bg = b == CapBtn.Close
                ? (_pressed == b ? Theme.Blend(Theme.AccentRed, Color.Black, 0.25f) : Theme.AccentRed)
                : (_pressed == b ? Theme.Blend(Theme.SurfaceHigh, Color.Black, 0.2f) : Theme.SurfaceHigh);
            using var brush = new SolidBrush(bg);
            g.FillRectangle(brush, r);
        }
        Color fg = b == CapBtn.Close && _hot == b ? Color.White : Theme.Text;
        Theme.DrawIcon(g, glyph, 9f, fg, r);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            _bg?.Dispose();
        base.Dispose(disposing);
    }
}
