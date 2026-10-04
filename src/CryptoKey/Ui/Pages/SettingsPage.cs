using System.Diagnostics;
using System.Security.Principal;

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
    private readonly ToggleSwitch _startupAdmin;
    private readonly AppButton _shortcutBtn;
    private readonly Slider _poll;
    private readonly Label _pollValue;
    private readonly bool _elevated;
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
            Height = 252,
            Margin = new Padding(0, 0, 0, 10),
        };
        var beh = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 6,
            BackColor = Theme.Surface,
            Padding = new Padding(0),
        };
        for (int i = 0; i < 6; i++)
            beh.RowStyles.Add(new RowStyle(SizeType.Percent, 100f / 6f));

        StartupMode startupMode = StartupManager.GetMode();
        _lockOnRemoval = Toggle("Auto-lock when the key is removed", _config.Guard.LockOnRemoval);
        _balloonTips = Toggle("Balloon notifications on lock/unlock", _config.Guard.BalloonTips);
        _animations = Toggle("Interface animations", _config.Guard.Animations);
        _startup = Toggle("Start with Windows", startupMode != StartupMode.Off);
        _startupAdmin = Toggle("Launch as administrator (stronger lock)",
            startupMode == StartupMode.Elevated);
        _startupAdmin.Enabled = _startup.Checked;
        _startupAdmin.Margin = new Padding(22, 0, 0, 0);

        var adminRow = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 1,
            BackColor = Theme.Surface,
            Margin = new Padding(0),
        };
        adminRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 74f));
        adminRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 26f));
        adminRow.Controls.Add(_startupAdmin);
        _elevated = new WindowsPrincipal(WindowsIdentity.GetCurrent())
            .IsInRole(WindowsBuiltInRole.Administrator);
        var restartAdmin = new AppButton
        {
            Text = _elevated ? "Running as admin" : "Restart as admin",
            Glyph = Glyphs.Shield,
            Variant = ButtonVariant.Ghost,
            Dock = DockStyle.Fill,
            Enabled = !_elevated,
            Margin = new Padding(8, 4, 0, 4),
        };
        restartAdmin.Click += (_, _) => RestartElevated();
        adminRow.Controls.Add(restartAdmin);

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
        beh.Controls.Add(adminRow);
        beh.Controls.Add(pollRow);
        behCard.Controls.Add(beh);

        // ---- Storage ----
        var storeCard = new CardPanel
        {
            Title = "Storage",
            Glyph = Glyphs.Folder,
            Dock = DockStyle.Top,
            Height = 140,
        };
        var store = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 2,
            BackColor = Theme.Surface,
            Padding = new Padding(0),
        };
        store.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 72f));
        store.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 28f));
        store.RowStyles.Add(new RowStyle(SizeType.Percent, 50f));
        store.RowStyles.Add(new RowStyle(SizeType.Percent, 50f));
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
        store.Controls.Add(pathLabel, 0, 0);
        store.Controls.Add(openFolder, 1, 0);
        var shortcutLabel = new Label
        {
            Text = "Start Menu shortcut",
            Font = Theme.UIFont(9f),
            ForeColor = Theme.TextDim,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            AutoSize = false,
        };
        _shortcutBtn = new AppButton
        {
            Glyph = ShortcutManager.Exists ? Glyphs.Close : Glyphs.Check,
            Variant = ButtonVariant.Ghost,
            Dock = DockStyle.Fill,
            Margin = new Padding(8, 0, 0, 0),
        };
        _shortcutBtn.Text = ShortcutManager.Exists ? "Remove" : "Create";
        _shortcutBtn.Click += (_, _) => ToggleShortcut();
        store.Controls.Add(shortcutLabel, 0, 1);
        store.Controls.Add(_shortcutBtn, 1, 1);
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
        _startup.CheckedChanged += (_, _) => ApplyStartupMode();
        _startupAdmin.CheckedChanged += (_, _) => ApplyStartupMode();
        _poll.ValueChanged += (_, _) =>
        {
            _pollValue.Text = $"{_poll.Value} ms";
            _service.ApplyPollInterval(_poll.Value);
            Save();
        };
    }

    private void ApplyStartupMode()
    {
        if (_suppressStartupEvent)
            return;
        _startupAdmin.Enabled = _startup.Checked;
        var mode = !_startup.Checked ? StartupMode.Off
            : _startupAdmin.Checked ? StartupMode.Elevated : StartupMode.Normal;

        // Writing (or removing) an elevated scheduled task needs admin — hand
        // it to an elevated helper instance instead of failing on Access denied.
        if (!_elevated && (mode == StartupMode.Elevated
                           || StartupManager.GetMode() == StartupMode.Elevated))
        {
            ApplyStartupModeElevated(mode);
            return;
        }

        try
        {
            StartupManager.SetMode(mode);
            NotifyStartupMode(mode);
        }
        catch (Exception ex)
        {
            _notify($"Startup change failed: {ex.Message}", true);
            ResyncStartupToggles();
        }
    }

    private void ApplyStartupModeElevated(StartupMode mode)
    {
        try
        {
            var p = Process.Start(new ProcessStartInfo(Application.ExecutablePath,
                    $"--set-startup {mode.ToString().ToLowerInvariant()}")
            {
                UseShellExecute = true,
                Verb = "runas",
            });
            if (p == null)
                throw new InvalidOperationException("helper did not start");
            _notify("Approve the UAC prompt to apply the startup change…", false);
            Task.Run(() =>
            {
                p.WaitForExit(90000);
                bool ok = p.ExitCode == 0;
                try { BeginInvoke(() => FinishElevatedStartup(ok, mode)); }
                catch (Exception) { }
            });
        }
        catch (Exception ex)
        {
            _notify($"Elevation cancelled: {ex.Message}", true);
            ResyncStartupToggles();
        }
    }

    private void FinishElevatedStartup(bool ok, StartupMode wanted)
    {
        ResyncStartupToggles();
        if (ok)
            NotifyStartupMode(wanted);
        else
            _notify("Startup change cancelled or failed", true);
    }

    private void NotifyStartupMode(StartupMode mode)
        => _notify(mode switch
        {
            StartupMode.Elevated => "Starts at login as administrator",
            StartupMode.Normal => "CryptoKey will start at login",
            _ => "Removed from login startup",
        }, false);

    private void ResyncStartupToggles()
    {
        _suppressStartupEvent = true;
        StartupMode actual = StartupManager.GetMode();
        _startup.Checked = actual != StartupMode.Off;
        _startupAdmin.Checked = actual == StartupMode.Elevated;
        _startupAdmin.Enabled = _startup.Checked;
        _suppressStartupEvent = false;
    }

    private void ToggleShortcut()
    {
        try
        {
            bool create = !ShortcutManager.Exists;
            ShortcutManager.SetEnabled(create);
            _shortcutBtn.Text = create ? "Remove" : "Create";
            _shortcutBtn.Glyph = create ? Glyphs.Close : Glyphs.Check;
            _notify(create ? "Start Menu shortcut created" : "Start Menu shortcut removed", false);
        }
        catch (Exception ex)
        {
            _notify($"Shortcut failed: {ex.Message}", true);
        }
    }

    private void RestartElevated()
    {
        try
        {
            Process.Start(new ProcessStartInfo(Application.ExecutablePath, "--takeover")
            {
                UseShellExecute = true,
                Verb = "runas",
            });
            Application.Exit();
        }
        catch (Exception ex)
        {
            _notify($"Elevation cancelled: {ex.Message}", true);
        }
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
