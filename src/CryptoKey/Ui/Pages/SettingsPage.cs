using System.Diagnostics;

namespace CryptoKey;

/// <summary>Behavior toggles, poll interval, storage info. Saves apply live.</summary>
internal sealed class SettingsPage : UserControl
{
    private readonly KeyConfig _config;
    private readonly GuardService _service;
    private readonly Action<string, bool> _notify;

    private readonly ToggleSwitch _lockOnRemoval;
    private readonly ToggleSwitch _balloonTips;
    private readonly ToggleSwitch _animations;
    private readonly ToggleSwitch _startup;
    private readonly Slider _poll;
    private readonly Label _pollValue;
    private bool _suppressStartupEvent;

    public SettingsPage(KeyConfig config, GuardService service, Action<string, bool> notify)
    {
        _config = config;
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
            RowCount = 2,
            BackColor = Theme.Bg,
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));

        // ---- Behavior ----
        var behCard = new CardPanel
        {
            Title = "Behavior",
            Glyph = Glyphs.Settings,
            Dock = DockStyle.Top,
            Height = 216,
            Margin = new Padding(0, 0, 0, 10),
        };
        var beh = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 5,
            BackColor = Theme.Surface,
            Padding = new Padding(0),
        };
        for (int i = 0; i < 5; i++)
            beh.RowStyles.Add(new RowStyle(SizeType.Percent, 20f));

        _lockOnRemoval = Toggle("Auto-lock when the key is removed", _config.Guard.LockOnRemoval);
        _balloonTips = Toggle("Balloon notifications on lock/unlock", _config.Guard.BalloonTips);
        _animations = Toggle("Interface animations", _config.Guard.Animations);
        _startup = Toggle("Start with Windows", StartupManager.IsEnabled);

        var pollRow = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 3,
            RowCount = 1,
            BackColor = Theme.Surface,
            Margin = new Padding(0),
        };
        pollRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 34f));
        pollRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 46f));
        pollRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 20f));
        var pollLabel = new Label
        {
            Text = "USB poll interval",
            Font = Theme.UIFont(9f),
            ForeColor = Theme.Text,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            AutoSize = false,
        };
        _poll = new Slider
        {
            Minimum = 250,
            Maximum = 10000,
            Step = 250,
            Value = Math.Clamp(_config.Guard.PollIntervalMs, 250, 10000),
            Dock = DockStyle.Fill,
            Margin = new Padding(6, 0, 6, 0),
        };
        _pollValue = new Label
        {
            Text = $"{_poll.Value} ms",
            Font = Theme.MonoFont(8.5f),
            ForeColor = Theme.TextDim,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleRight,
            AutoSize = false,
        };
        pollRow.Controls.Add(pollLabel);
        pollRow.Controls.Add(_poll);
        pollRow.Controls.Add(_pollValue);

        beh.Controls.Add(_lockOnRemoval);
        beh.Controls.Add(_balloonTips);
        beh.Controls.Add(_animations);
        beh.Controls.Add(_startup);
        beh.Controls.Add(pollRow);
        behCard.Controls.Add(beh);

        // ---- Storage ----
        var storeCard = new CardPanel
        {
            Title = "Storage",
            Glyph = Glyphs.Folder,
            Dock = DockStyle.Top,
            Height = 96,
        };
        var store = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 1,
            BackColor = Theme.Surface,
            Padding = new Padding(0),
        };
        store.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 72f));
        store.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 28f));
        var pathLabel = new Label
        {
            Text = ConfigStore.ConfigPath,
            Font = Theme.MonoFont(8f),
            ForeColor = Theme.TextDim,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            AutoEllipsis = true,
            AutoSize = false,
        };
        var openFolder = new AppButton
        {
            Text = "Open folder",
            Glyph = Glyphs.Folder,
            Variant = ButtonVariant.Ghost,
            Dock = DockStyle.Fill,
            Margin = new Padding(8, 0, 0, 0),
        };
        openFolder.Click += (_, _) =>
        {
            try
            {
                Process.Start(new ProcessStartInfo("explorer.exe", ConfigStore.ConfigDir)
                { UseShellExecute = true });
            }
            catch (Exception ex) { _notify(ex.Message, true); }
        };
        store.Controls.Add(pathLabel);
        store.Controls.Add(openFolder);
        storeCard.Controls.Add(store);

        layout.Controls.Add(behCard, 0, 0);
        layout.Controls.Add(storeCard, 0, 1);
        Controls.Add(layout);

        _lockOnRemoval.CheckedChanged += (_, _) => Save();
        _balloonTips.CheckedChanged += (_, _) => Save();
        _animations.CheckedChanged += (_, _) =>
        {
            _config.Guard.Animations = _animations.Checked;
            Animator.Enabled = _animations.Checked;
            _service.ApplyMotion(_animations.Checked);
            Save();
        };
        _startup.CheckedChanged += (_, _) =>
        {
            if (_suppressStartupEvent)
                return;
            try
            {
                StartupManager.SetEnabled(_startup.Checked);
                _notify(_startup.Checked
                    ? "CryptoKey will start at login" : "Removed from login startup", false);
            }
            catch (Exception ex)
            {
                _notify($"Startup change failed: {ex.Message}", true);
                _suppressStartupEvent = true;
                _startup.Checked = !_startup.Checked;
                _suppressStartupEvent = false;
            }
        };
        _poll.ValueChanged += (_, _) =>
        {
            _pollValue.Text = $"{_poll.Value} ms";
            _service.ApplyPollInterval(_poll.Value);
            Save();
        };
    }

    private static ToggleSwitch Toggle(string text, bool on)
        => new()
        {
            Text = text,
            Checked = on,
            Dock = DockStyle.Fill,
        };

    private void Save()
    {
        _config.Guard.LockOnRemoval = _lockOnRemoval.Checked;
        _config.Guard.BalloonTips = _balloonTips.Checked;
        _config.Guard.PollIntervalMs = _poll.Value;
        try
        {
            ConfigStore.Save(_config);
        }
        catch (Exception ex)
        {
            _notify($"Save failed: {ex.Message}", true);
        }
    }
}
