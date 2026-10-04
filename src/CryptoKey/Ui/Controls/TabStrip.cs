using System.Drawing.Drawing2D;

namespace CryptoKey;

internal sealed record TabItem(string Title, string Glyph);

/// <summary>Fluent-style tab strip: glyph tabs, sliding accent indicator, hover fades.</summary>
internal sealed class TabStrip : Control
{
    private readonly List<TabItem> _tabs = new();
    private readonly List<float> _hovers = new();
    private int _selected;
    private int _hot = -1;
    private float _indicatorX;
    private float _indicatorW;
    private bool _indicatorInit;

    public event EventHandler? SelectedIndexChanged;

    public TabStrip()
    {
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint
            | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw
            | ControlStyles.Selectable, true);
        BackColor = Theme.Bg;
        Font = Theme.UIFont(9f);
        Height = 44;
        TabStop = true;
    }

    public IReadOnlyList<TabItem> Tabs => _tabs;

    public int SelectedIndex
    {
        get => _selected;
        set
        {
            int v = Math.Clamp(value, 0, Math.Max(0, _tabs.Count - 1));
            if (v == _selected)
                return;
            _selected = v;
            MoveIndicator(animated: true);
            Invalidate();
            SelectedIndexChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    public void AddTab(string title, string glyph)
    {
        _tabs.Add(new TabItem(title, glyph));
        _hovers.Add(0f);
        Invalidate();
    }

    private RectangleF TabRect(int i)
    {
        float w = Width / (float)Math.Max(1, _tabs.Count);
        return new RectangleF(i * w, 0, w, Height);
    }

    private int TabAt(Point p)
    {
        for (int i = 0; i < _tabs.Count; i++)
            if (TabRect(i).Contains(p))
                return i;
        return -1;
    }

    private void MoveIndicator(bool animated)
    {
        if (_tabs.Count == 0)
            return;
        RectangleF r = TabRect(_selected);
        float targetX = r.X + r.Width * 0.25f;
        float targetW = r.Width * 0.5f;
        if (!_indicatorInit || !animated || !IsHandleCreated)
        {
            _indicatorX = targetX;
            _indicatorW = targetW;
            _indicatorInit = true;
            return;
        }
        float fx = _indicatorX, fw = _indicatorW;
        Animator.Run(220, t =>
        {
            _indicatorX = fx + (targetX - fx) * t;
            _indicatorW = fw + (targetW - fw) * t;
            Invalidate();
        });
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        int hot = TabAt(e.Location);
        if (hot == _hot)
            return;
        int prev = _hot;
        _hot = hot;
        Cursor = hot >= 0 ? Cursors.Hand : Cursors.Default;
        if (hot >= 0)
            AnimateHover(hot, 1f);
        if (prev >= 0)
            AnimateHover(prev, 0f);
    }

    protected override void OnMouseLeave(EventArgs e)
    {
        base.OnMouseLeave(e);
        if (_hot >= 0)
            AnimateHover(_hot, 0f);
        _hot = -1;
        Cursor = Cursors.Default;
    }

    protected override void OnMouseDown(MouseEventArgs e)
    {
        base.OnMouseDown(e);
        if (e.Button == MouseButtons.Left)
        {
            Focus();
            int i = TabAt(e.Location);
            if (i >= 0)
                SelectedIndex = i;
        }
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        base.OnKeyDown(e);
        if (e.KeyCode == Keys.Left && _selected > 0)
        {
            SelectedIndex--;
            e.Handled = true;
        }
        else if (e.KeyCode == Keys.Right && _selected < _tabs.Count - 1)
        {
            SelectedIndex++;
            e.Handled = true;
        }
    }

    protected override void OnResize(EventArgs e)
    {
        base.OnResize(e);
        _indicatorInit = false;
        MoveIndicator(animated: false);
    }

    private void AnimateHover(int i, float target)
    {
        float from = _hovers[i];
        Animator.Run(140, t => { _hovers[i] = from + (target - from) * t; Invalidate(); });
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        Graphics g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(BackColor);
        g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

        for (int i = 0; i < _tabs.Count; i++)
        {
            RectangleF r = TabRect(i);
            bool selected = i == _selected;

            if (_hovers[i] > 0.01f && !selected)
            {
                using var hover = new SolidBrush(
                    Theme.WithAlpha(Theme.SurfaceHigh, (int)(_hovers[i] * 160)));
                g.FillPath(hover, Theme.RoundedRect(
                    new RectangleF(r.X + 8f, 6f, r.Width - 16f, Height - 12f), Theme.RadiusSmall));
            }

            Color fg = selected ? Theme.Text : Theme.Blend(Theme.TextDim, Theme.Text, _hovers[i]);
            float cx = r.X + r.Width / 2f;
            using (var fgBrush = new SolidBrush(fg))
            {
                var fmt = new StringFormat
                {
                    Alignment = StringAlignment.Center,
                    LineAlignment = StringAlignment.Center,
                };
                using var glyphFont = Glyphs.Font(10f);
                SizeF glyphSize = g.MeasureString(_tabs[i].Glyph, glyphFont);
                SizeF textSize = g.MeasureString(_tabs[i].Title, Font);
                float total = glyphSize.Width + 6f + textSize.Width;
                float x = cx - total / 2f;
                var cy = new RectangleF(0, 0, 0, Height);
                g.DrawString(_tabs[i].Glyph, glyphFont, fgBrush,
                    new RectangleF(x, 0, glyphSize.Width, Height), fmt);
                g.DrawString(_tabs[i].Title, Font, fgBrush,
                    new RectangleF(x + glyphSize.Width + 6f, 0, textSize.Width + 8f, Height), fmt);
            }
        }

        if (_tabs.Count > 0)
        {
            using var brush = new SolidBrush(Theme.Accent);
            g.FillPath(brush, Theme.RoundedRect(
                new RectangleF(_indicatorX, Height - 3f, _indicatorW, 3f), 1.5f));
        }
        using var linePen = new Pen(Theme.Border, 1f);
        g.DrawLine(linePen, 0, Height - 0.5f, Width, Height - 0.5f);
    }
}
