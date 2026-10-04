using System.Drawing.Drawing2D;

namespace CryptoKey;

/// <summary>Animated Fluent-style pill toggle. Owner-drawn CheckBox.</summary>
internal sealed class ToggleSwitch : CheckBox
{
    private const int TrackW = 44;
    private const int TrackH = 22;

    private float _thumb;

    public ToggleSwitch()
    {
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint
            | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        BackColor = Theme.Surface;
        Font = Theme.UIFont(9f);
        Height = TrackH + 4;
        AutoSize = false;
    }

    protected override void OnCheckedChanged(EventArgs e)
    {
        base.OnCheckedChanged(e);
        float from = _thumb;
        float to = Checked ? 1f : 0f;
        if (!IsHandleCreated)
        {
            _thumb = to;
            return;
        }
        Animator.Run(160, t => { _thumb = from + (to - from) * t; Invalidate(); });
    }

    public override Size GetPreferredSize(Size proposedSize)
    {
        using var g = CreateGraphics();
        int textW = (int)g.MeasureString(Text, Font).Width;
        return new Size(TrackW + 10 + textW + 8, TrackH + 4);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        Graphics g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(BackColor);

        float cy = Height / 2f;
        var track = new RectangleF(1f, cy - TrackH / 2f, TrackW, TrackH);

        Color trackFill = Checked
            ? Theme.WithAlpha(Theme.Accent, 200)
            : Theme.SurfaceHigh;
        Color trackBorder = Checked ? Theme.Accent : Theme.Border;

        using (var path = Theme.RoundedRect(track, TrackH / 2f))
        using (var brush = new SolidBrush(trackFill))
            g.FillPath(brush, path);
        using (var path = Theme.RoundedRect(track, TrackH / 2f))
        using (var pen = new Pen(trackBorder, 1f))
            g.DrawPath(pen, path);

        float thumbD = TrackH - 8f;
        float thumbX = track.X + 4f + _thumb * (track.Width - thumbD - 8f);
        using (var brush = new SolidBrush(Checked ? Theme.BgDeep : Theme.TextDim))
            g.FillEllipse(brush, thumbX, cy - thumbD / 2f, thumbD, thumbD);

        using var textBrush = new SolidBrush(Enabled ? Theme.Text : Theme.TextDim);
        var fmt = new StringFormat
        {
            LineAlignment = StringAlignment.Center,
            Trimming = StringTrimming.EllipsisCharacter,
        };
        g.DrawString(Text, Font, textBrush,
            new RectangleF(TrackW + 10f, 0, Width - TrackW - 10f, Height), fmt);
    }
}
