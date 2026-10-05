namespace CryptoKey;

/// <summary>Identity, update status, what-it-does, and the honest limitations list.</summary>
internal sealed class AboutPage : UserControl
{
    private readonly GuardService _service;
    private readonly Action<string, bool> _notify;
    private readonly Label _updStatus;
    private readonly AppButton _applyBtn;
    private bool _checking;

    public AboutPage(GuardService service, Action<string, bool> notify)
    {
        _service = service;
        _notify = notify;
        DoubleBuffered = true;
        BackColor = Theme.Bg;
        Padding = new Padding(20, 12, 20, 16);
        AutoScroll = true;

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            ColumnCount = 1,
            RowCount = 4,
            BackColor = Theme.Bg,
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));

        // ---- Identity ----
        var idCard = new CardPanel
        {
            Dock = DockStyle.Top,
            Height = 120,
            Margin = new Padding(0, 0, 0, 10),
        };
        var brand = new Label
        {
            Text = "CryptoKey",
            Font = Theme.DisplayFont(20f, FontStyle.Bold),
            ForeColor = Theme.Text,
            AutoSize = true,
            Location = new Point(16, 20),
        };
        var tag = new Label
        {
            Text = "Turn a USB drive into a physical key for your PC. Pull it out — " +
                   "the screen locks. Put it back — you are in.",
            Font = Theme.UIFont(9f),
            ForeColor = Theme.TextDim,
            AutoSize = true,
            MaximumSize = new Size(560, 0),
            Location = new Point(16, 56),
        };
        var ver = new Label
        {
            Text = $"v{Application.ProductVersion}",
            Font = Theme.MonoFont(8f),
            ForeColor = Theme.TextDim,
            AutoSize = true,
            Location = new Point(16, 92),
        };
        idCard.Controls.AddRange(new Control[] { brand, tag, ver });

        // ---- Updates ----
        var updCard = new CardPanel
        {
            Title = "Updates",
            Glyph = Glyphs.Download,
            Dock = DockStyle.Top,
            Height = 132,
            Margin = new Padding(0, 0, 0, 10),
        };
        var updInner = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2,
            BackColor = Theme.Surface,
            Padding = new Padding(0),
        };
        updInner.RowStyles.Add(new RowStyle(SizeType.Percent, 55f));
        updInner.RowStyles.Add(new RowStyle(SizeType.Percent, 45f));

        _updStatus = new Label
        {
            Text = "Signed releases checked daily — updates are never installed " +
                   "without you asking.",
            Font = Theme.UIFont(8.5f),
            ForeColor = Theme.TextDim,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
        };
        updInner.Controls.Add(_updStatus, 0, 0);

        var updBtns = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 3,
            RowCount = 1,
            BackColor = Theme.Surface,
            Margin = new Padding(0),
        };
        updBtns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33f));
        updBtns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33f));
        updBtns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 34f));
        var checkBtn = new AppButton
        {
            Text = "Check now",
            Glyph = Glyphs.Refresh,
            Variant = ButtonVariant.Secondary,
            Dock = DockStyle.Fill,
            Margin = new Padding(0, 4, 4, 4),
        };
        checkBtn.Click += (_, _) =>
        {
            _checking = true;
            _updStatus.Text = "Checking for updates…";
            // "ok checking" replies instantly; the result lands via the
            // next snapshot (StateChanged → RefreshUpdateState).
            string reply = _service.DispatchCommand("update check");
            if (!reply.StartsWith("ok", StringComparison.Ordinal))
            {
                _checking = false;
                _updStatus.Text = reply;
            }
        };
        _applyBtn = new AppButton
        {
            Text = "Install update",
            Glyph = Glyphs.Download,
            Variant = ButtonVariant.Primary,
            Dock = DockStyle.Fill,
            Margin = new Padding(4, 4, 4, 4),
            Enabled = false,
        };
        _applyBtn.Click += (_, _) =>
        {
            string reply = _service.DispatchCommand("update apply");
            _notify(reply.StartsWith("ok", StringComparison.Ordinal)
                ? "Applying — the app restarts on the new build."
                : reply, !reply.StartsWith("ok", StringComparison.Ordinal));
            RefreshUpdateState();
        };
        updBtns.Controls.Add(checkBtn, 0, 0);
        updBtns.Controls.Add(_applyBtn, 1, 0);
        updInner.Controls.Add(updBtns, 0, 1);
        updCard.Controls.Add(updInner);

        // ---- Limitations ----
        var limCard = new CardPanel
        {
            Title = "Know the limits",
            Glyph = Glyphs.Warning,
            Dock = DockStyle.Top,
            Height = 176,
            Margin = new Padding(0, 0, 0, 10),
        };
        string[] lines =
        {
            "Ctrl+Alt+Del and the security desktop cannot be blocked.",
            "Task Manager can end the process — the lock dies with it.",
            "Elevated windows may resist the input hooks.",
            "The On-Screen Keyboard bypasses the keyboard hook if opened first.",
            "A deterrent and convenience lock — not a complete security boundary.",
        };
        var limInner = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = lines.Length,
            BackColor = Theme.Surface,
            Padding = new Padding(0),
        };
        for (int i = 0; i < lines.Length; i++)
            limInner.RowStyles.Add(new RowStyle(SizeType.Percent, 100f / lines.Length));
        for (int i = 0; i < lines.Length; i++)
        {
            limInner.Controls.Add(new Label
            {
                Text = $"•  {lines[i]}",
                Font = Theme.UIFont(8.5f),
                ForeColor = i == lines.Length - 1 ? Theme.AccentAmber : Theme.TextDim,
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
            }, 0, i);
        }
        limCard.Controls.Add(limInner);

        // ---- Commands ----
        var cmdCard = new CardPanel
        {
            Title = "Commands",
            Glyph = Glyphs.Info,
            Dock = DockStyle.Top,
            Height = 128,
        };
        var cmdLabel = new Label
        {
            Text = "cryptokey            launch this app\n" +
                   "cryptokey enroll     register a USB drive\n" +
                   "cryptokey lock       lock now\n" +
                   "cryptokey update     check for a new build\n" +
                   "cryptokey status     live guard state",
            Font = Theme.MonoFont(8f),
            ForeColor = Theme.TextDim,
            Dock = DockStyle.Fill,
            Padding = new Padding(0),
        };
        cmdCard.Controls.Add(cmdLabel);

        layout.Controls.Add(idCard, 0, 0);
        layout.Controls.Add(updCard, 0, 1);
        layout.Controls.Add(limCard, 0, 2);
        layout.Controls.Add(cmdCard, 0, 3);
        Controls.Add(layout);

        _service.StateChanged += OnGuardState;
        RefreshUpdateState();
    }

    // Any snapshot post-click means the check resolved — the pending flag
    // inside it is the answer (null = up to date, or the check failed and
    // we fall back to the last-known state).
    private void OnGuardState(StatusSnapshot snap)
    {
        _checking = false;
        RefreshUpdateState();
    }

    private void RefreshUpdateState()
    {
        if (IsDisposed)
            return;
        string? pending = _service.PendingUpdate?.TagName;
        _applyBtn.Enabled = pending != null;
        _updStatus.Text = _checking
            ? "Checking for updates…"
            : pending != null
                ? $"Update available: {pending} — signed release verified on download."
                : "Up to date — releases are signed; nothing installs without you asking.";
        _updStatus.ForeColor = pending != null && !_checking ? Theme.Accent : Theme.TextDim;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            _service.StateChanged -= OnGuardState;
        base.Dispose(disposing);
    }
}
