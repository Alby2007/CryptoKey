namespace CryptoKey;

/// <summary>
/// Main window: live guard state, key status, and action buttons.
/// Closing it hides to the tray — the guard keeps running; Quit stays on the
/// tray menu and only while unlocked.
/// </summary>
internal sealed class DashboardForm : Form
{
    private readonly GuardService _service;
    private readonly KeyConfig _config;
    private readonly TrayIcons _icons;
    private readonly List<Font> _fonts = new();

    private readonly Label _stateLabel;
    private readonly Label _keyStatus;
    private readonly Label _keyDetail;
    private readonly Button _lockBtn;
    private readonly Button _resumeBtn;
    private readonly Button _pause5;
    private readonly Button _pause15;
    private readonly Button _pause60;
    private SettingsForm? _settings;

    public DashboardForm(GuardService service, KeyConfig config, TrayIcons icons, bool devMode)
    {
        _service = service;
        _config = config;
        _icons = icons;

        Text = "CryptoKey";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(430, 470);

        Font titleFont = MakeFont(15f, FontStyle.Bold);
        Font sectionFont = MakeFont(9f, FontStyle.Bold);
        Font stateFont = MakeFont(13f, FontStyle.Bold);

        Controls.Add(new Label
        {
            Text = "CryptoKey",
            Font = titleFont,
            AutoSize = true,
            Location = new Point(14, 10),
        });
        _stateLabel = new Label
        {
            Font = stateFont,
            AutoSize = true,
            Location = new Point(14, 40),
        };
        Controls.Add(_stateLabel);

        // ---- Key ----
        Panel keyCard = Card(14, 74, 402, 96);
        keyCard.Controls.Add(SectionTitle("KEY", sectionFont, 10, 10));
        _keyStatus = new Label { AutoSize = true, Location = new Point(12, 34) };
        _keyDetail = new Label
        {
            AutoSize = true,
            ForeColor = Theme.TextDim,
            Location = new Point(12, 56),
        };
        keyCard.Controls.AddRange(new Control[] { _keyStatus, _keyDetail });
        Controls.Add(keyCard);

        // ---- Actions ----
        Panel actCard = Card(14, 180, 402, 150);
        actCard.Controls.Add(SectionTitle("ACTIONS", sectionFont, 10, 10));
        _lockBtn = MakeButton("Lock now", 12, 36, 120, accent: true);
        _lockBtn.Click += (_, _) => _service.RequestLock();
        _resumeBtn = MakeButton("Resume", 140, 36, 120);
        _resumeBtn.Click += (_, _) => _service.Resume();
        var pauseLabel = new Label
        {
            Text = "Pause auto-lock for:",
            AutoSize = true,
            ForeColor = Theme.TextDim,
            Location = new Point(12, 82),
        };
        _pause5 = MakeButton("5 min", 12, 106, 80);
        _pause15 = MakeButton("15 min", 100, 106, 80);
        _pause60 = MakeButton("60 min", 188, 106, 80);
        _pause5.Click += (_, _) => _service.Pause(5, out _);
        _pause15.Click += (_, _) => _service.Pause(15, out _);
        _pause60.Click += (_, _) => _service.Pause(60, out _);
        actCard.Controls.AddRange(new Control[]
            { _lockBtn, _resumeBtn, pauseLabel, _pause5, _pause15, _pause60 });
        Controls.Add(actCard);

        if (devMode)
        {
            Controls.Add(new Label
            {
                Text = "DEV MODE — Ctrl+Alt+Shift+F12 kills the guard.",
                ForeColor = Theme.AccentAmber,
                AutoSize = true,
                Location = new Point(14, 342),
            });
        }

        var settingsBtn = MakeButton("Settings…", 14, 424, 120);
        settingsBtn.Click += (_, _) => ShowSettings();
        Controls.Add(settingsBtn);
        var hideBtn = MakeButton("Hide to tray", 296, 424, 120);
        hideBtn.Click += (_, _) => Hide();
        Controls.Add(hideBtn);

        _ = Handle;
        Theme.Apply(this);

        _service.StateChanged += OnStateChanged;
        OnStateChanged(_service.Snapshot());
    }

    private void OnStateChanged(StatusSnapshot snap) => ApplySnapshot(snap);

    private void ApplySnapshot(StatusSnapshot snap)
    {
        Icon = _icons.For(snap.State);
        switch (snap.State)
        {
            case GuardState.Locked:
                _stateLabel.Text = "LOCKED";
                _stateLabel.ForeColor = Theme.AccentRed;
                break;
            case GuardState.Paused:
                _stateLabel.Text = $"PAUSED — until {snap.PausedUntil:HH:mm}";
                _stateLabel.ForeColor = Theme.AccentAmber;
                break;
            default:
                _stateLabel.Text = "UNLOCKED";
                _stateLabel.ForeColor = Theme.AccentGreen;
                break;
        }

        if (snap.KeyPresent)
        {
            _keyStatus.Text = snap.LastVerifyFailure != null
                ? $"Present — {snap.LastVerifyFailure}"
                : "Present — verified";
            _keyDetail.Text = $"{snap.Model} — serial {_config.DeviceSerial}";
        }
        else
        {
            _keyStatus.Text = "Absent";
            _keyDetail.Text = $"serial {_config.DeviceSerial}";
        }

        _lockBtn.Enabled = snap.State != GuardState.Locked;
        _resumeBtn.Enabled = snap.State == GuardState.Paused;
        _pause5.Enabled = _pause15.Enabled = _pause60.Enabled = snap.State == GuardState.Unlocked;
    }

    private void ShowSettings()
    {
        if (_settings is { IsDisposed: false })
        {
            _settings.Activate();
            return;
        }
        _settings = new SettingsForm(_config, _service);
        _settings.FormClosed += (_, _) => _settings = null;
        _settings.Show(this);
    }

    private Font MakeFont(float size, FontStyle style)
    {
        var f = Theme.UIFont(size, style);
        _fonts.Add(f);
        return f;
    }

    private static Panel Card(int x, int y, int w, int h)
    {
        var p = Theme.Card();
        p.SetBounds(x, y, w, h);
        return p;
    }

    private static Label SectionTitle(string text, Font font, int x, int y)
        => new()
        {
            Text = text,
            Font = font,
            ForeColor = Theme.TextDim,
            AutoSize = true,
            Location = new Point(x, y),
        };

    private static Button MakeButton(string text, int x, int y, int w, bool accent = false)
    {
        var b = new Button
        {
            Text = text,
            Location = new Point(x, y),
            Width = w,
            Height = 30,
        };
        Theme.StyleButton(b, accent);
        return b;
    }

    // Close = hide to tray. The guard keeps running; quitting lives on the
    // tray menu and only while unlocked.
    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (e.CloseReason is CloseReason.UserClosing or CloseReason.TaskManagerClosing)
        {
            e.Cancel = true;
            Hide();
            return;
        }
        base.OnFormClosing(e);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _service.StateChanged -= OnStateChanged;
            _settings?.Dispose();
            foreach (Font f in _fonts)
                f.Dispose();
        }
        base.Dispose(disposing);
    }
}
