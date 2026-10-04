namespace CryptoKey;

/// <summary>Hero status, key card, actions, and a live activity feed.</summary>
internal sealed class DashboardPage : UserControl
{
    private readonly GuardService _service;
    private readonly KeyConfig _config;

    private readonly StatusHero _hero;
    private readonly Label _stateLabel;
    private readonly Label _reasonLabel;
    private readonly Badge _keyBadge;
    private readonly Badge _cloneBadge;
    private readonly Badge _devBadge;
    private readonly Badge _wdBadge;
    private readonly Label _keyModel;
    private readonly Label _keySerial;
    private readonly Label _keyVolume;
    private readonly AppButton _lockBtn;
    private readonly AppButton _resumeBtn;
    private readonly AppButton _pause5;
    private readonly AppButton _pause15;
    private readonly AppButton _pause60;
    private readonly ListBox _activity;
    private StatusSnapshot? _last;

    public DashboardPage(GuardService service, KeyConfig config, bool devMode)
    {
        _service = service;
        _config = config;
        DoubleBuffered = true;
        BackColor = Theme.Bg;
        Padding = new Padding(20, 12, 20, 16);

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 3,
            BackColor = Theme.Bg,
        };
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 216f));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 148f));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));

        // ---- Hero ----
        var heroPanel = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 3,
            BackColor = Theme.Bg,
        };
        heroPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 152f));
        heroPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 30f));
        heroPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));

        _hero = new StatusHero { Size = new Size(148, 148), Anchor = AnchorStyles.None };
        _stateLabel = new Label
        {
            Font = Theme.DisplayFont(15f, FontStyle.Bold),
            ForeColor = Theme.AccentGreen,
            AutoSize = true,
            Anchor = AnchorStyles.None,
        };
        var subRow = new FlowLayoutPanel
        {
            AutoSize = true,
            Anchor = AnchorStyles.None,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            BackColor = Theme.Bg,
        };
        _reasonLabel = new Label
        {
            Font = Theme.UIFont(9f),
            ForeColor = Theme.TextDim,
            AutoSize = true,
            Margin = new Padding(0, 2, 8, 0),
        };
        _keyBadge = new Badge
        {
            Text = "key",
            Margin = new Padding(0, 1, 6, 0),
        };
        _cloneBadge = new Badge
        {
            Text = "possible clone",
            BadgeColor = Theme.AccentRed,
            Visible = false,
            Margin = new Padding(0, 1, 6, 0),
        };
        _devBadge = new Badge
        {
            Text = "dev mode",
            BadgeColor = Theme.AccentAmber,
            Visible = devMode,
            Margin = new Padding(0, 1, 6, 0),
        };
        _wdBadge = new Badge
        {
            Text = "watchdog",
            BadgeColor = Theme.Accent,
            Visible = false,
        };
        subRow.Controls.AddRange(new Control[]
            { _reasonLabel, _keyBadge, _cloneBadge, _devBadge, _wdBadge });
        heroPanel.Controls.Add(_hero, 0, 0);
        heroPanel.Controls.Add(_stateLabel, 0, 1);
        heroPanel.Controls.Add(subRow, 0, 2);

        // ---- Key + Actions row ----
        var mid = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 1,
            BackColor = Theme.Bg,
        };
        mid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 52f));
        mid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 48f));

        var keyCard = new CardPanel
        {
            Title = "Enrolled key",
            Glyph = Glyphs.Usb,
            Dock = DockStyle.Fill,
            Margin = new Padding(0, 0, 6, 0),
        };
        var keyInner = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 3,
            BackColor = Theme.Surface,
            Padding = new Padding(0),
        };
        keyInner.RowStyles.Add(new RowStyle(SizeType.Percent, 40f));
        keyInner.RowStyles.Add(new RowStyle(SizeType.Percent, 30f));
        keyInner.RowStyles.Add(new RowStyle(SizeType.Percent, 30f));
        _keyModel = new Label
        {
            Font = Theme.UIFont(9.5f, FontStyle.Bold),
            ForeColor = Theme.Text,
            AutoSize = true,
            Anchor = AnchorStyles.Left,
        };
        _keySerial = new Label
        {
            Font = Theme.MonoFont(8.5f),
            ForeColor = Theme.TextDim,
            AutoSize = true,
            Anchor = AnchorStyles.Left,
        };
        _keyVolume = new Label
        {
            Font = Theme.UIFont(8.5f),
            ForeColor = Theme.TextDim,
            AutoSize = true,
            Anchor = AnchorStyles.Left,
        };
        keyInner.Controls.Add(_keyModel, 0, 0);
        keyInner.Controls.Add(_keySerial, 0, 1);
        keyInner.Controls.Add(_keyVolume, 0, 2);
        keyCard.Controls.Add(keyInner);

        var actCard = new CardPanel
        {
            Title = "Actions",
            Glyph = Glyphs.Shield,
            Dock = DockStyle.Fill,
            Margin = new Padding(6, 0, 0, 0),
        };
        var actInner = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2,
            BackColor = Theme.Surface,
            Padding = new Padding(0),
        };
        actInner.RowStyles.Add(new RowStyle(SizeType.Percent, 52f));
        actInner.RowStyles.Add(new RowStyle(SizeType.Percent, 48f));

        var topRow = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 1,
            BackColor = Theme.Surface,
            Margin = new Padding(0),
        };
        topRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50f));
        topRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50f));

        _lockBtn = new AppButton
        {
            Text = "Lock now",
            Glyph = Glyphs.Lock,
            Variant = ButtonVariant.Primary,
            Dock = DockStyle.Fill,
            Margin = new Padding(0, 0, 4, 6),
        };
        _lockBtn.Click += (_, _) => _service.RequestLock();
        _resumeBtn = new AppButton
        {
            Text = "Resume",
            Glyph = Glyphs.Play,
            Variant = ButtonVariant.Secondary,
            Dock = DockStyle.Fill,
            Margin = new Padding(4, 0, 0, 6),
        };
        _resumeBtn.Click += (_, _) => _service.Resume();
        topRow.Controls.Add(_lockBtn, 0, 0);
        topRow.Controls.Add(_resumeBtn, 1, 0);

        var pauseRow = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 4,
            RowCount = 1,
            BackColor = Theme.Surface,
            Margin = new Padding(0),
        };
        pauseRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 22f));
        pauseRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 26f));
        pauseRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 26f));
        pauseRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 26f));

        _pause5 = PauseButton(5);
        _pause15 = PauseButton(15);
        _pause60 = PauseButton(60);
        var pauseHint = new Label
        {
            Text = "pause",
            Font = Theme.UIFont(8f),
            ForeColor = Theme.TextDim,
            AutoSize = false,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            Margin = new Padding(0, 0, 4, 0),
        };
        pauseRow.Controls.Add(pauseHint, 0, 0);
        pauseRow.Controls.Add(_pause5, 1, 0);
        pauseRow.Controls.Add(_pause15, 2, 0);
        pauseRow.Controls.Add(_pause60, 3, 0);

        actInner.Controls.Add(topRow, 0, 0);
        actInner.Controls.Add(pauseRow, 0, 1);
        actCard.Controls.Add(actInner);

        mid.Controls.Add(keyCard, 0, 0);
        mid.Controls.Add(actCard, 1, 0);

        // ---- Activity ----
        var actFeedCard = new CardPanel
        {
            Title = "Activity",
            Glyph = Glyphs.Activity,
            Dock = DockStyle.Fill,
            Margin = new Padding(0, 10, 0, 0),
        };
        _activity = new ListBox
        {
            Dock = DockStyle.Fill,
            BackColor = Theme.Surface,
            ForeColor = Theme.TextDim,
            BorderStyle = BorderStyle.None,
            Font = Theme.MonoFont(8f),
            IntegralHeight = false,
            Margin = new Padding(0),
        };
        var feedInner = new Panel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(0),
            BackColor = Theme.Surface,
        };
        feedInner.Controls.Add(_activity);
        actFeedCard.Controls.Add(feedInner);

        layout.Controls.Add(heroPanel, 0, 0);
        layout.Controls.Add(mid, 0, 1);
        layout.Controls.Add(actFeedCard, 0, 2);
        Controls.Add(layout);

        foreach (string line in _service.RecentActivity)
            _activity.Items.Insert(0, line);
        _service.ActivityLogged += OnActivity;

        ApplySnapshot(_service.Snapshot());
    }

    private AppButton PauseButton(int mins)
    {
        var b = new AppButton
        {
            Text = $"{mins}m",
            Variant = ButtonVariant.Secondary,
            Dock = DockStyle.Fill,
            Margin = new Padding(4, 0, 0, 0),
            Font = Theme.UIFont(8f),
        };
        b.Click += (_, _) => _service.Pause(mins, out _);
        return b;
    }

    private void OnActivity(string line)
    {
        if (IsDisposed || !IsHandleCreated)
            return;
        _activity.Items.Insert(0, line);
        while (_activity.Items.Count > 200)
            _activity.Items.RemoveAt(_activity.Items.Count - 1);
    }

    public void ApplySnapshot(StatusSnapshot snap)
    {
        _last = snap;
        _hero.SetSnapshot(snap);

        switch (snap.State)
        {
            case GuardState.Locked:
                _stateLabel.Text = "LOCKED";
                _stateLabel.ForeColor = Theme.AccentRed;
                // Armed-while-locked only happens under 2FA — the key factor
                // is satisfied and the passphrase completes the unlock.
                _reasonLabel.Text = snap.KeyFactorArmed
                    ? "key verified — enter the passphrase"
                    : snap.LastVerifyFailure != null
                        ? snap.LastVerifyFailure
                        : "key absent";
                break;
            case GuardState.Paused:
                _stateLabel.Text = "PAUSED";
                _stateLabel.ForeColor = Theme.AccentAmber;
                _reasonLabel.Text = $"auto-lock resumes {snap.PausedUntil:HH:mm}";
                break;
            default:
                _stateLabel.Text = "ARMED";
                _stateLabel.ForeColor = Theme.AccentGreen;
                _reasonLabel.Text = snap.KeyPresent
                    ? "pull the key to lock"
                    : "waiting for key";
                break;
        }

        if (snap.KeyPresent)
        {
            _keyBadge.Text = snap.LastVerifyFailure != null ? "unverified" : "verified";
            _keyBadge.BadgeColor = snap.LastVerifyFailure != null
                ? Theme.AccentRed : Theme.AccentGreen;
            _keyModel.Text = snap.Model ?? "USB drive";
            _keySerial.Text = $"serial {_config.DeviceSerial}";
            _keyVolume.Text = snap.LastVerifyFailure
                ?? $"keyfile verified — generation {_config.RotationCount}";
        }
        else
        {
            _keyBadge.Text = "absent";
            _keyBadge.BadgeColor = Theme.TextDim;
            _keyModel.Text = "Key not detected";
            _keySerial.Text = $"serial {_config.DeviceSerial}";
            _keyVolume.Text = "insert the enrolled drive";
        }
        _cloneBadge.Visible = snap.TamperNote != null;
        _wdBadge.Visible = snap.WatchdogAlive;
        _keyBadge.Size = _keyBadge.GetPreferredSize(Size.Empty);
        _cloneBadge.Size = _cloneBadge.GetPreferredSize(Size.Empty);
        _devBadge.Size = _devBadge.GetPreferredSize(Size.Empty);
        _wdBadge.Size = _wdBadge.GetPreferredSize(Size.Empty);

        _lockBtn.Enabled = snap.State != GuardState.Locked;
        _resumeBtn.Enabled = snap.State == GuardState.Paused;
        _resumeBtn.Variant = snap.State == GuardState.Paused
            ? ButtonVariant.Primary : ButtonVariant.Secondary;
        _pause5.Enabled = _pause15.Enabled = _pause60.Enabled
            = snap.State != GuardState.Locked; // a pause can be extended
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            _service.ActivityLogged -= OnActivity;
        base.Dispose(disposing);
    }
}
