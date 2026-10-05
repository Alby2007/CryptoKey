using System.Drawing.Drawing2D;

namespace CryptoKey;

/// <summary>Small status pill: tinted rounded rect + text.</summary>
internal sealed class Badge : Control
{
    private Color _color = Theme.TextDim;

    public Color BadgeColor
    {
        get => _color;
        set { _color = value; Invalidate(); }
    }

    public Badge()
    {
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint
            | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        BackColor = Theme.Bg;
        Font = Theme.UIFont(7.5f, FontStyle.Bold);
        Size = new Size(80, 20);
    }

    public override Size GetPreferredSize(Size proposedSize)
    {
        using var g = CreateGraphics();
        int w = (int)g.MeasureString(Text?.ToUpperInvariant() ?? "", Font).Width;
        return new Size(w + 22, 20);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        Graphics g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(BackColor);

        var rect = new RectangleF(0.5f, 0.5f, Width - 1f, Height - 1f);
        using (var path = Theme.RoundedRect(rect, Height / 2f))
        using (var fill = new SolidBrush(Theme.WithAlpha(_color, 30)))
            g.FillPath(fill, path);
        using (var path = Theme.RoundedRect(rect, Height / 2f))
        using (var pen = new Pen(Theme.WithAlpha(_color, 140), 1f))
            g.DrawPath(pen, path);

        using var brush = new SolidBrush(_color);
        var fmt = new StringFormat
        {
            Alignment = StringAlignment.Center,
            LineAlignment = StringAlignment.Center,
        };
        g.DrawString(Text?.ToUpperInvariant() ?? "", Font, brush, rect, fmt);
    }
}
