using System.Drawing.Drawing2D;

namespace CryptoKey;

/// <summary>
/// One borderless topmost lock overlay. <paramref name="bounds"/> decides the
/// coverage: the classic surface creates one per screen (primary gets the
/// full glass lock card, secondaries get minimal branding); the secure
/// surface creates a single form spanning <see cref="SystemInformation.VirtualScreen"/>.
/// A 33ms animation tick repaints (cheap — cached background) so painting can
/// never starve the low-level input hooks on the same thread.
/// </summary>
internal sealed class LockForm : Form
{
    private const string DefaultStatus =
        "Insert your CryptoKey, or type your recovery phrase and press Enter.";

    // Shared fonts — app lifetime, never disposed.
    private static readonly Font ClockFont = Theme.DisplayFont(30f, FontStyle.Bold);
    private static readonly Font DateFont = Theme.UIFont(10f);
    private static readonly Font TitleFont = Theme.DisplayFont(17f, FontStyle.Bold);
    private static readonly Font SubFont = Theme.UIFont(9.5f);
    private static readonly Font BrandFont = Theme.DisplayFont(13f, FontStyle.Bold);
    private static readonly StringFormat Center = new()
    {
        Alignment = StringAlignment.Center,
        LineAlignment = StringAlignment.Center,
    };

    public Rectangle CoverBounds { get; }

    private readonly bool _primary;
    private readonly System.Windows.Forms.Timer _anim;
    private Bitmap? _bg;
    private Rectangle _dirtyRect;   // scoped repaint region — recomputed on resize
    private float _phase;
    private float _shake = -1f;   // <0 inactive, 0..1 progress
    private float _flash;
    private string _status = DefaultStatus;
    private int _passLen;
    private int _attempts;
    private DateTime? _cooldownUntil;

    public LockForm(Rectangle bounds, bool primary)
    {
        _primary = primary;
        FormBorderStyle = FormBorderStyle.None;
        StartPosition = FormStartPosition.Manual;
        BackColor = Theme.BgDeep;
        TopMost = true;
        ShowInTaskbar = false;
        DoubleBuffered = true;
        Cursor = Cursors.No;
        CoverBounds = bounds;
        Bounds = bounds;

        _anim = new System.Windows.Forms.Timer { Interval = 33 };
        _anim.Tick += (_, _) =>
        {
            _phase += 0.04f;
            if (_phase > MathF.PI * 2f)
                _phase -= MathF.PI * 2f;
            if (_shake >= 0f)
            {
                _shake += 0.055f;
                if (_shake >= 1f)
                    _shake = -1f;
            }
            if (_flash > 0f)
                _flash = Math.Max(0f, _flash - 0.06f);
            Repaint();
        };
        UpdateDirtyRect();
    }

    /// <summary>
    /// Every animated pixel lives inside the card zone: the card is
    /// deterministic (480×430 centered), shake displaces it ±10px, and the
    /// key art's ambient glow bleeds ~40px past its rect — card inflated by
    /// 48 covers the worst case. Secondary forms animate only inside their
    /// centered art+text band. ~10× less repaint work per monitor.
    /// </summary>
    private void UpdateDirtyRect()
    {
        RectangleF r;
        if (_primary)
        {
            r = new RectangleF((Width - 480f) / 2f, (Height - 430f) / 2f, 480f, 430f);
            r.Inflate(48f, 48f);
        }
        else
        {
            float cy = Height / 2f;
            r = new RectangleF(0, cy - 125f, Width, 215f);
        }
        _dirtyRect = Rectangle.Ceiling(RectangleF.Intersect(r,
            new RectangleF(0, 0, Width, Height)));
    }

    private void Repaint()
        => Invalidate(_dirtyRect.IsEmpty ? ClientRectangle : _dirtyRect);

    private bool _animationsOn = true;

    public void SetAnimations(bool enabled)
    {
        _animationsOn = enabled;
        UpdateTimer();
        Repaint();
    }

    private void UpdateTimer()
    {
        if (!Visible)
        {
            _anim.Stop();
            return;
        }
        _anim.Interval = _animationsOn ? 33 : 1000; // 1s clock-only tick when reduced
        _anim.Start();
    }

    protected override void OnVisibleChanged(EventArgs e)
    {
        base.OnVisibleChanged(e);
        UpdateTimer();
    }

    public void SetPassphraseLength(int len)
    {
        _passLen = len;
        Repaint();
    }

    public void SetStatus(string message)
    {
        _status = message;
        Repaint();
    }

    public void ResetStatus() => SetStatus(DefaultStatus);

    public void SetFailedAttempts(int count)
    {
        _attempts = count;
        if (count > 0 && Visible)
        {
            _shake = 0f;
            _flash = 1f;
        }
        Repaint();
    }

    public void SetCooldown(DateTime? until)
    {
        _cooldownUntil = until;
        Repaint();
    }

    protected override void OnSizeChanged(EventArgs e)
    {
        base.OnSizeChanged(e);
        _bg?.Dispose();
        _bg = null;
        UpdateDirtyRect();   // the card moved — and a resize repaints fully anyway
    }

    private void EnsureBackground()
    {
        if (_bg != null || Width <= 0 || Height <= 0)
            return;
        _bg = new Bitmap(Width, Height);
        using var g = Graphics.FromImage(_bg);
        using (var grad = new LinearGradientBrush(
            new Rectangle(0, 0, Width, Height),
            Theme.BgDeep, Theme.Bg, LinearGradientMode.Vertical))
            g.FillRectangle(grad, 0, 0, Width, Height);

        // Two static mood glows.
        RadialGlow(g, Width * 0.85f, -Height * 0.10f, Width * 0.45f,
            Theme.WithAlpha(Theme.Accent, 16));
        RadialGlow(g, -Width * 0.10f, Height * 1.10f, Width * 0.45f,
            Theme.WithAlpha(Theme.AccentRed, 14));
    }

    private void RadialGlow(Graphics g, float cx, float cy, float r, Color c)
    {
        var pts = new PointF[8];
        for (int i = 0; i < 8; i++)
        {
            double a = i * Math.PI / 4.0;
            pts[i] = new PointF(cx + (float)(Math.Cos(a) * r), cy + (float)(Math.Sin(a) * r));
        }
        using var brush = new PathGradientBrush(pts);
        brush.CenterColor = c;
        brush.SurroundColors = new[] { Color.Transparent };
        g.FillRectangle(brush, 0, 0, Width, Height);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        Graphics g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

        EnsureBackground();
        if (_bg != null)
            g.DrawImageUnscaled(_bg, 0, 0);
        else
            g.Clear(Theme.BgDeep);

        if (_primary)
            PaintPrimary(g);
        else
            PaintSecondary(g);
    }

    private void PaintSecondary(Graphics g)
    {
        float cx = Width / 2f, cy = Height / 2f;
        KeyArtRenderer.Draw(g, new RectangleF(cx - 110f, cy - 64f, 220f, 96f),
            eject: 1.0, Theme.AccentRed, _phase);
        using var brush = new SolidBrush(Theme.WithAlpha(Theme.TextDim, 180));
        g.DrawString("CRYPTOKEY", BrandFont, brush,
            new RectangleF(0, cy + 52f, Width, 26f), Center);
    }

    private void PaintPrimary(Graphics g)
    {
        const float cardW = 480f, cardH = 430f;
        float shakeX = _shake >= 0f
            ? MathF.Sin(_shake * 24f) * 10f * (1f - _shake) : 0f;
        var card = new RectangleF(
            (Width - cardW) / 2f + shakeX, (Height - cardH) / 2f, cardW, cardH);

        // Glass card.
        using (var path = Theme.RoundedRect(card, 18f))
        using (var fill = new SolidBrush(Theme.WithAlpha(Theme.Surface, 235)))
            g.FillPath(fill, path);
        Color border = Theme.Blend(Theme.Border, Theme.AccentRed, _flash);
        using (var path = Theme.RoundedRect(card, 18f))
        using (var pen = new Pen(border, 1f + _flash * 1.5f))
            g.DrawPath(pen, path);

        float cx = card.X + card.Width / 2f;
        float y = card.Y + 34f;

        // Clock + date.
        using (var brush = new SolidBrush(Theme.WithAlpha(Theme.Text, 225)))
            g.DrawString(DateTime.Now.ToString("HH:mm"), ClockFont, brush,
                new RectangleF(card.X, y, card.Width, 42f), Center);
        using (var brush = new SolidBrush(Theme.TextDim))
            g.DrawString(DateTime.Now.ToString("dddd, MMMM d"), DateFont, brush,
                new RectangleF(card.X, y + 44f, card.Width, 20f), Center);

        // The signature element: the key ejected from its port, ring and
        // LED breathing in the locked color.
        KeyArtRenderer.Draw(g, new RectangleF(cx - 140f, card.Y + 88f, 280f, 122f),
            eject: 1.0, Theme.AccentRed, _phase);

        // Title + status.
        using (var brush = new SolidBrush(Theme.Text))
            g.DrawString("LOCKED", TitleFont, brush,
                new RectangleF(card.X, card.Y + 216f, card.Width, 28f), Center);
        using (var brush = new SolidBrush(Theme.TextDim))
            g.DrawString(_status, SubFont, brush,
                new RectangleF(card.X + 24f, card.Y + 248f, card.Width - 48f, 20f), Center);

        // Phrase dots — replaced by the cooldown countdown while
        // input is frozen (tick repaints, so it self-clears on expiry).
        float dy = card.Y + 296f;
        if (_cooldownUntil is DateTime until && DateTime.Now < until)
        {
            int secs = (int)Math.Ceiling((until - DateTime.Now).TotalSeconds);
            using var brush = new SolidBrush(Theme.AccentAmber);
            g.DrawString($"input frozen — try again in {secs}s", SubFont, brush,
                new RectangleF(card.X, dy - 6f, card.Width, 20f), Center);
        }
        else
        {
            int dots = Math.Min(_passLen, 20);
            float dotD = 9f, gap = 15f;
            float totalW = dots * gap - (gap - dotD);
            float dx = cx - totalW / 2f;
            using (var dotBrush = new SolidBrush(Theme.Accent))
            {
                for (int i = 0; i < dots; i++)
                    g.FillEllipse(dotBrush, dx + i * gap, dy, dotD, dotD);
            }
            if (_passLen == 0)
            {
                using var brush = new SolidBrush(Theme.WithAlpha(Theme.TextDim, 120));
                g.DrawString("type your recovery phrase", SubFont, brush,
                    new RectangleF(card.X, dy - 6f, card.Width, 20f), Center);
            }
        }

        // Failed-attempts pill.
        if (_attempts > 0)
        {
            string msg = $"failed attempts: {_attempts}";
            using var brush = new SolidBrush(Theme.WithAlpha(Theme.AccentRed, 26));
            using var pen = new Pen(Theme.WithAlpha(Theme.AccentRed, 160), 1f);
            float pw = 150f, ph = 24f;
            var pill = new RectangleF(cx - pw / 2f, card.Y + 334f, pw, ph);
            using (var path = Theme.RoundedRect(pill, ph / 2f))
                g.FillPath(brush, path);
            using (var path = Theme.RoundedRect(pill, ph / 2f))
                g.DrawPath(pen, path);
            using var textBrush = new SolidBrush(Theme.AccentRed);
            g.DrawString(msg, SubFont, textBrush, pill, Center);
        }

        // Bottom hint.
        float pulse = MathF.Sin(_phase) * 0.5f + 0.5f;
        using (var brush = new SolidBrush(
            Theme.WithAlpha(Theme.TextDim, (int)(120 + pulse * 80))))
        {
            Theme.DrawIcon(g, Glyphs.Usb, 11f,
                Theme.WithAlpha(Theme.TextDim, (int)(120 + pulse * 80)),
                new RectangleF(cx - 96f, card.Bottom - 36f, 18f, 18f));
            g.DrawString("insert your CryptoKey", SubFont, brush,
                new RectangleF(cx - 76f, card.Bottom - 37f, 160f, 20f),
                new StringFormat { LineAlignment = StringAlignment.Center });
        }
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        // Resist user close and Task Manager "End task" (WM_CLOSE), but
        // never ApplicationExit or WindowsShutDown — canceling those
        // silently aborts Application.Exit() (the panic combo) and can
        // stall Windows logoff.
        if (e.CloseReason is CloseReason.UserClosing or CloseReason.TaskManagerClosing)
            e.Cancel = true;
        base.OnFormClosing(e);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _anim.Dispose();
            _bg?.Dispose();
        }
        base.Dispose(disposing);
    }
}
