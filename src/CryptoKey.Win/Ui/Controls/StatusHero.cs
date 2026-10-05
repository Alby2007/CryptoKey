using System.Drawing.Drawing2D;

namespace CryptoKey;

/// <summary>
/// The centerpiece ring: state-colored glowing circle with a padlock glyph,
/// breathing pulse, animated color transitions, and a countdown arc while paused.
/// </summary>
internal sealed class StatusHero : Control
{
    private GuardState _state = GuardState.Unlocked;
    private Color _color = Theme.AccentGreen;
    private DateTime? _pausedUntil;
    private DateTime _pauseStart;
    private float _phase;
    private readonly System.Windows.Forms.Timer _anim;

    public StatusHero()
    {
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint
            | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        SetStyle(ControlStyles.Selectable, false);
        BackColor = Theme.Bg;
        Size = new Size(180, 180);

        _anim = new System.Windows.Forms.Timer { Interval = 33 };
        _anim.Tick += (_, _) =>
        {
            _phase += 0.035f;
            if (_phase > MathF.PI * 2f)
                _phase -= MathF.PI * 2f;
            Invalidate();
        };
    }

    public void SetSnapshot(StatusSnapshot snap)
    {
        bool wasPaused = _state == GuardState.Paused;
        _pausedUntil = snap.PausedUntil;
        if (snap.State == GuardState.Paused && !wasPaused)
            _pauseStart = DateTime.Now;

        Color target = ColorFor(snap.State);
        _state = snap.State;
        if (target != _color)
        {
            Color from = _color;
            Animator.Run(350, t => { _color = Theme.Blend(from, target, t); Invalidate(); });
        }

        bool run = Animator.Enabled && Visible;
        if (run && !_anim.Enabled)
            _anim.Start();
        else if (!run && _anim.Enabled)
            _anim.Stop();
        Invalidate();
    }

    public static Color ColorFor(GuardState state) => state switch
    {
        GuardState.Locked => Theme.AccentRed,
        GuardState.Paused => Theme.AccentAmber,
        _ => Theme.AccentGreen,
    };

    protected override void OnVisibleChanged(EventArgs e)
    {
        base.OnVisibleChanged(e);
        if (!Visible && _anim.Enabled)
            _anim.Stop();
        else if (Visible && Animator.Enabled && !_anim.Enabled)
            _anim.Start();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        Graphics g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(BackColor);

        float cx = Width / 2f;
        float cy = Height / 2f;
        float baseR = Math.Min(Width, Height) / 2f - 26f;
        float pulse = MathF.Sin(_phase) * 0.5f + 0.5f;        // 0..1 breathing
        float r = baseR + pulse * 2.5f;

        Theme.DrawGlow(g, cx, cy, r, Theme.WithAlpha(_color, (int)(60 + pulse * 90)));

        using (var ringPen = new Pen(_color, 5.5f))
        {
            ringPen.StartCap = ringPen.EndCap = LineCap.Round;
            g.DrawEllipse(ringPen, cx - r, cy - r, r * 2f, r * 2f);
        }

        // Countdown arc while paused — drains as the deadline approaches.
        if (_state == GuardState.Paused && _pausedUntil is DateTime until)
        {
            double total = Math.Max(1.0, (until - _pauseStart).TotalSeconds);
            double left = Math.Clamp((until - DateTime.Now).TotalSeconds, 0, total);
            float sweep = (float)(left / total * 360.0);
            using var arcPen = new Pen(Theme.WithAlpha(Color.White, 200), 2f);
            arcPen.StartCap = arcPen.EndCap = LineCap.Round;
            g.DrawArc(arcPen, cx - r, cy - r, r * 2f, r * 2f, -90f, sweep);
        }

        string glyph = _state switch
        {
            GuardState.Locked => Glyphs.Lock,
            GuardState.Paused => Glyphs.Pause,
            _ => Glyphs.Unlock,
        };
        float iconSize = r * 0.55f;
        Theme.DrawIcon(g, glyph, iconSize, _color,
            new RectangleF(cx - r, cy - r, r * 2f, r * 2f));
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            _anim.Dispose();
        base.Dispose(disposing);
    }
}
