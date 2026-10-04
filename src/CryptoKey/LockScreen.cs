using System.Drawing.Drawing2D;

namespace CryptoKey;

/// <summary>
/// One borderless topmost overlay per monitor. Primary screen gets the full
/// glass lock card (padlock ring, clock, passphrase dots, shake-on-fail);
/// secondary screens get minimal branding. A 250ms watchdog re-asserts
/// topmost to fight focus stealers. Animation is opt-out via config and kept
/// light (cached background, small invalidations) so painting can never
/// starve the low-level input hooks running on the same thread.
/// </summary>
internal sealed class LockScreen : IDisposable
{
    private const string DefaultStatus =
        "Insert your CryptoKey, or type the failsafe passphrase and press Enter.";

    /// <summary>Raised after each topmost re-assert (lets the input locker re-clip).</summary>
    public event Action? ReassertTick;

    private readonly List<LockForm> _forms = new();
    private readonly System.Windows.Forms.Timer _topmostTimer;
    private bool _visible;
    private bool _animations = true;
    private string _status = DefaultStatus;
    private int _passLen;
    private int _failedAttempts;

    public LockScreen()
    {
        BuildForms();

        _topmostTimer = new System.Windows.Forms.Timer { Interval = 250 };
        _topmostTimer.Tick += (_, _) =>
        {
            EnsureCoverage();
            ReassertTopmost();
        };
    }

    public void Show()
    {
        EnsureCoverage();
        _visible = true;
        foreach (LockForm f in _forms)
            f.Show();
        ReassertTopmost();
        _topmostTimer.Start();
    }

    public void Hide()
    {
        _visible = false;
        _topmostTimer.Stop();
        foreach (LockForm f in _forms)
            f.Hide();
    }

    public void SetAnimations(bool enabled)
    {
        _animations = enabled;
        foreach (LockForm f in _forms)
            f.SetAnimations(enabled);
    }

    public void SetPassphraseLength(int len)
    {
        _passLen = len;
        foreach (LockForm f in _forms)
            f.SetPassphraseLength(len);
    }

    public void SetStatus(string message)
    {
        _status = message;
        foreach (LockForm f in _forms)
            f.SetStatus(message);
    }

    public void SetFailedAttempts(int count)
    {
        _failedAttempts = count;
        foreach (LockForm f in _forms)
            f.SetFailedAttempts(count);
    }

    private void BuildForms()
    {
        Screen[] screens = Screen.AllScreens;
        for (int i = 0; i < screens.Length; i++)
        {
            var f = new LockForm(screens[i], i == 0);
            f.SetAnimations(_animations);
            f.SetStatus(_status);
            f.SetPassphraseLength(_passLen);
            f.SetFailedAttempts(_failedAttempts);
            _forms.Add(f);
        }
    }

    // Displays can appear while locked (dock, monitor wake, display mode
    // change). Keep one form per current screen so nothing goes uncovered.
    private void EnsureCoverage()
    {
        Screen[] screens = Screen.AllScreens;
        bool current = screens.Length == _forms.Count
            && _forms.Zip(screens).All(pair => pair.First.ScreenBounds == pair.Second.Bounds);
        if (current)
            return;

        var old = _forms.ToList();
        _forms.Clear();
        BuildForms();
        if (_visible)
        {
            foreach (LockForm f in _forms)
                f.Show();
        }
        foreach (LockForm f in old)
            f.Dispose();
    }

    public void ResetStatus() => SetStatus(DefaultStatus);

    private void ReassertTopmost()
    {
        LockForm? foreground = null;
        foreach (LockForm f in _forms)
        {
            if (f.IsDisposed)
                continue;
            NativeMethods.SetWindowPos(f.Handle, NativeMethods.HWND_TOPMOST, 0, 0, 0, 0,
                NativeMethods.SWP_NOMOVE | NativeMethods.SWP_NOSIZE | NativeMethods.SWP_SHOWWINDOW);
            f.Activate();
            foreground ??= f;
        }
        if (foreground != null)
            NativeMethods.SetForegroundWindow(foreground.Handle);
        ReassertTick?.Invoke();
    }

    public void Dispose()
    {
        _topmostTimer.Dispose();
        foreach (LockForm f in _forms)
            f.Dispose();
        _forms.Clear();
    }

    // ---------------------------------------------------------------

    private sealed class LockForm : Form
    {
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

        public Rectangle ScreenBounds { get; }

        private readonly bool _primary;
        private readonly System.Windows.Forms.Timer _anim;
        private Bitmap? _bg;
        private float _phase;
        private float _shake = -1f;   // <0 inactive, 0..1 progress
        private float _flash;
        private string _status = DefaultStatus;
        private int _passLen;
        private int _attempts;

        public LockForm(Screen screen, bool primary)
        {
            _primary = primary;
            FormBorderStyle = FormBorderStyle.None;
            StartPosition = FormStartPosition.Manual;
            BackColor = Theme.BgDeep;
            TopMost = true;
            ShowInTaskbar = false;
            DoubleBuffered = true;
            Cursor = Cursors.No;
            ScreenBounds = screen.Bounds;
            Bounds = screen.Bounds;

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
                Invalidate();
            };
        }

        private bool _animationsOn = true;

        public void SetAnimations(bool enabled)
        {
            _animationsOn = enabled;
            UpdateTimer();
            Invalidate();
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
            Invalidate();
        }

        public void SetStatus(string message)
        {
            _status = message;
            Invalidate();
        }

        public void SetFailedAttempts(int count)
        {
            _attempts = count;
            if (count > 0 && Visible)
            {
                _shake = 0f;
                _flash = 1f;
            }
            Invalidate();
        }

        protected override void OnSizeChanged(EventArgs e)
        {
            base.OnSizeChanged(e);
            _bg?.Dispose();
            _bg = null;
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
            float r = 34f + MathF.Sin(_phase) * 2f;
            Theme.DrawGlow(g, cx, cy, r, Theme.WithAlpha(Theme.AccentRed, 60), 4);
            using var pen = new Pen(Theme.AccentRed, 4f);
            g.DrawEllipse(pen, cx - r, cy - r, r * 2, r * 2);
            Theme.DrawIcon(g, Glyphs.Lock, 26f, Theme.AccentRed,
                new RectangleF(cx - r, cy - r, r * 2, r * 2));
            using var brush = new SolidBrush(Theme.WithAlpha(Theme.TextDim, 180));
            g.DrawString("CRYPTOKEY", BrandFont, brush,
                new RectangleF(0, cy + r + 14f, Width, 26f), Center);
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

            // Padlock ring — breathing.
            float ringR = 46f + MathF.Sin(_phase) * 2.5f;
            float ringY = card.Y + 158f;
            Theme.DrawGlow(g, cx, ringY, ringR,
                Theme.WithAlpha(Theme.AccentRed, (int)(80 + MathF.Sin(_phase) * 30 + 30)));
            using (var ringPen = new Pen(Theme.AccentRed, 5f))
                g.DrawEllipse(ringPen, cx - ringR, ringY - ringR, ringR * 2, ringR * 2);
            Theme.DrawIcon(g, Glyphs.Lock, 34f, Theme.AccentRed,
                new RectangleF(cx - ringR, ringY - ringR, ringR * 2, ringR * 2));

            // Title + status.
            using (var brush = new SolidBrush(Theme.Text))
                g.DrawString("LOCKED", TitleFont, brush,
                    new RectangleF(card.X, card.Y + 216f, card.Width, 28f), Center);
            using (var brush = new SolidBrush(Theme.TextDim))
                g.DrawString(_status, SubFont, brush,
                    new RectangleF(card.X + 24f, card.Y + 248f, card.Width - 48f, 20f), Center);

            // Passphrase dots.
            int dots = Math.Min(_passLen, 20);
            float dotD = 9f, gap = 15f;
            float totalW = dots * gap - (gap - dotD);
            float dx = cx - totalW / 2f;
            float dy = card.Y + 296f;
            using (var dotBrush = new SolidBrush(Theme.Accent))
            {
                for (int i = 0; i < dots; i++)
                    g.FillEllipse(dotBrush, dx + i * gap, dy, dotD, dotD);
            }
            if (_passLen == 0)
            {
                using var brush = new SolidBrush(Theme.WithAlpha(Theme.TextDim, 120));
                g.DrawString("type your passphrase", SubFont, brush,
                    new RectangleF(card.X, dy - 6f, card.Width, 20f), Center);
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
}
