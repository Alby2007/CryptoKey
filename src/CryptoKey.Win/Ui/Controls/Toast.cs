using System.Drawing.Drawing2D;

namespace CryptoKey;

/// <summary>Transient floating notification pill — slides in, holds, fades out.</summary>
internal sealed class Toast : Control
{
    private float _alpha;
    private Color _color = Theme.AccentGreen;
    private string _glyph = Glyphs.Check;
    private System.Windows.Forms.Timer? _hideTimer;

    public Toast()
    {
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint
            | ControlStyles.OptimizedDoubleBuffer, true);
        SetStyle(ControlStyles.Selectable, false);
        BackColor = Theme.Bg;
        Visible = false;
        Size = new Size(220, 32);
        Font = Theme.UIFont(8.5f);
    }

    public void Show(string message, bool isError = false)
    {
        Text = message;
        _color = isError ? Theme.AccentRed : Theme.AccentGreen;
        _glyph = isError ? Glyphs.Warning : Glyphs.Check;
        using (var g = CreateGraphics())
            Width = (int)g.MeasureString(message, Font).Width + 52;

        _hideTimer?.Stop();
        _hideTimer ??= new System.Windows.Forms.Timer { Interval = 2600 };
        _hideTimer.Tick -= OnHide;
        _hideTimer.Tick += OnHide;

        Visible = true;
        float from = _alpha;
        Animator.Run(200, t => { _alpha = from + (1f - from) * t; Invalidate(); },
            done: () => _hideTimer.Start());
        BringToFront();
    }

    private void OnHide(object? s, EventArgs e)
    {
        _hideTimer?.Stop();
        float from = _alpha;
        Animator.Run(260, t => { _alpha = from * (1f - t); Invalidate(); },
            done: () => Visible = false);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        Graphics g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(BackColor);
        if (_alpha < 0.01f)
            return;
        int a = (int)(_alpha * 255);

        var rect = new RectangleF(0.5f, 0.5f, Width - 1f, Height - 1f);
        using (var path = Theme.RoundedRect(rect, Height / 2f))
        using (var fill = new SolidBrush(Theme.WithAlpha(Theme.SurfaceHigh, a)))
            g.FillPath(fill, path);
        using (var path = Theme.RoundedRect(rect, Height / 2f))
        using (var pen = new Pen(Theme.WithAlpha(_color, (int)(a * 0.7f)), 1f))
            g.DrawPath(pen, path);

        Theme.DrawIcon(g, _glyph, 10f, Theme.WithAlpha(_color, a),
            new RectangleF(10f, 0, 20f, Height));
        using var brush = new SolidBrush(Theme.WithAlpha(Theme.Text, a));
        var fmt = new StringFormat { LineAlignment = StringAlignment.Center };
        g.DrawString(Text, Font, brush, new RectangleF(34f, 0, Width - 34f, Height), fmt);
    }
}
