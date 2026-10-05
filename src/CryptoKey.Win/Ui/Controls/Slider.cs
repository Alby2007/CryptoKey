using System.Drawing.Drawing2D;

namespace CryptoKey;

/// <summary>Minimal dark slider: rounded track, filled portion, draggable thumb.</summary>
internal sealed class Slider : Control
{
    private int _minimum;
    private int _maximum = 100;
    private int _value;
    private int _step = 1;
    private bool _dragging;
    private float _hover;

    public event EventHandler? ValueChanged;

    public Slider()
    {
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint
            | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        BackColor = Theme.Surface;
        Height = 26;
        TabStop = true;
    }

    public int Minimum
    {
        get => _minimum;
        set
        {
            _minimum = value;
            if (_maximum < _minimum)
                _maximum = _minimum;
            Coerce();
        }
    }

    public int Maximum
    {
        get => _maximum;
        set { _maximum = Math.Max(value, _minimum); Coerce(); }
    }

    public int Step { get => _step; set => _step = Math.Max(1, value); }

    public int Value
    {
        get => _value;
        set
        {
            int v = Math.Clamp(Snap(value), _minimum, _maximum);
            if (v == _value)
                return;
            _value = v;
            Invalidate();
            ValueChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    private int Snap(int v) => _minimum + (int)Math.Round((v - _minimum) / (float)_step) * _step;
    private void Coerce() => Value = _value;

    private float Fraction
        => _maximum > _minimum ? (_value - _minimum) / (float)(_maximum - _minimum) : 0f;

    private float TrackX => 7f;
    private float TrackW => Width - 14f;

    private int ValueAt(int x)
        => _minimum + (int)Math.Round((x - TrackX) / TrackW * (_maximum - _minimum));

    protected override void OnMouseDown(MouseEventArgs e)
    {
        base.OnMouseDown(e);
        if (e.Button != MouseButtons.Left)
            return;
        _dragging = true;
        Capture = true;
        Focus();
        Value = ValueAt(e.X);
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        if (_dragging)
            Value = ValueAt(e.X);
    }

    protected override void OnMouseUp(MouseEventArgs e)
    {
        _dragging = false;
        Capture = false;
        base.OnMouseUp(e);
    }

    protected override void OnMouseEnter(EventArgs e)
    {
        base.OnMouseEnter(e);
        float from = _hover;
        Animator.Run(120, t => { _hover = from + (1f - from) * t; Invalidate(); });
    }

    protected override void OnMouseLeave(EventArgs e)
    {
        base.OnMouseLeave(e);
        float from = _hover;
        Animator.Run(120, t => { _hover = from * (1f - t); Invalidate(); });
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        base.OnKeyDown(e);
        int page = (_maximum - _minimum) / 10;
        switch (e.KeyCode)
        {
            case Keys.Left: case Keys.Down: Value = _value - _step; e.Handled = true; break;
            case Keys.Right: case Keys.Up: Value = _value + _step; e.Handled = true; break;
            case Keys.PageDown: Value = _value - page; e.Handled = true; break;
            case Keys.PageUp: Value = _value + page; e.Handled = true; break;
            case Keys.Home: Value = _minimum; e.Handled = true; break;
            case Keys.End: Value = _maximum; e.Handled = true; break;
        }
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        Graphics g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(BackColor);

        float cy = Height / 2f;
        float thumbX = TrackX + Fraction * TrackW;

        using (var brush = new SolidBrush(Theme.SurfaceHigh))
            g.FillPath(brush, Theme.RoundedRect(new RectangleF(TrackX, cy - 2.5f, TrackW, 5f), 2.5f));
        using (var brush = new SolidBrush(Theme.Accent))
            g.FillPath(brush, Theme.RoundedRect(
                new RectangleF(TrackX, cy - 2.5f, Math.Max(5f, thumbX - TrackX), 5f), 2.5f));

        float d = 14f + _hover * 2f;
        using (var brush = new SolidBrush(Color.White))
            g.FillEllipse(brush, thumbX - d / 2f, cy - d / 2f, d, d);
        using (var pen = new Pen(Theme.Accent, 2f))
            g.DrawEllipse(pen, thumbX - d / 2f, cy - d / 2f, d, d);
    }
}
