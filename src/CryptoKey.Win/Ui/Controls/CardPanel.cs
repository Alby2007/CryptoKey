using System.Drawing.Drawing2D;

namespace CryptoKey;

/// <summary>Rounded, bordered surface card with an optional glyph header.</summary>
internal sealed class CardPanel : Panel
{
    private string? _title;
    private string? _glyph;

    public string? Title
    {
        get => _title;
        set
        {
            _title = value;
            Padding = new Padding(16, value != null ? 42 : 16, 16, 14);
            Invalidate();
        }
    }

    public string? Glyph
    {
        get => _glyph;
        set { _glyph = value; Invalidate(); }
    }

    /// <summary>Top inset for children when a header is drawn.</summary>
    public int ContentTop => _title != null ? 40 : 12;

    public CardPanel()
    {
        DoubleBuffered = true;
        BackColor = Theme.Bg;
        Padding = new Padding(16);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        Graphics g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(BackColor);

        var rect = new RectangleF(0.5f, 0.5f, Width - 1f, Height - 1f);
        using (var path = Theme.RoundedRect(rect, Theme.Radius))
        using (var fill = new SolidBrush(Theme.Surface))
            g.FillPath(fill, path);

        if (_title != null)
        {
            float x = 16f;
            float cy = 20f;
            if (_glyph != null)
            {
                Theme.DrawIcon(g, _glyph, 13f, Theme.Accent,
                    new RectangleF(x, cy - 9f, 20f, 18f));
                x += 26f;
            }
            using var titleFont = Theme.UIFont(8f, FontStyle.Bold);
            using var titleBrush = new SolidBrush(Theme.TextDim);
            var fmt = new StringFormat { LineAlignment = StringAlignment.Center };
            g.DrawString(_title.ToUpperInvariant(), titleFont, titleBrush,
                new RectangleF(x, cy - 9f, Width - x - 16f, 18f), fmt);
        }

        using (var path = Theme.RoundedRect(rect, Theme.Radius))
        using (var pen = new Pen(Theme.Border, 1f))
            g.DrawPath(pen, path);
    }
}
