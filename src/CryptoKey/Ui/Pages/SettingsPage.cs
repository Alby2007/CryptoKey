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
    private readonly ToggleSwitch _sounds;
    private readonly ToggleSwitch _startup;
    private readonly ToggleSwitch _startupAdmin;
    private readonly ToggleSwitch _watchdog;
    private readonly ToggleSwitch _lockPolicies;
    private readonly ToggleSwitch _strictTamper;
    private readonly ToggleSwitch _privateDesktop;
    private readonly AppButton[] _policyBtns;
    private readonly Label _policyWarn;
    private UnlockPolicy _policy;
    private readonly AppButton _shortcutBtn;
    private readonly AppButton _desktopShortcutBtn;
    private readonly Slider _poll;
    private readonly Label _pollValue;
    private readonly Slider _idle;
    private readonly Label _idleValue;
    private readonly ToggleSwitch _webcam;
    private readonly TextField _alertUrl;
    private readonly bool _elevated;
    private bool _suppressStartupEvent;
    // Slider drags fire ValueChanged per tick — debounce the disk write.
    private readonly System.Windows.Forms.Timer _pollSave = new() { Interval = 500 };

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
            RowCount = 4,
            BackColor = Theme.Bg,
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));

        // ---- Behavior ----
        var behCard = new CardPanel
        {
            Title = "Behavior",
            Glyph = Glyphs.Settings,
            Dock = DockStyle.Top,
            Height = 374,
            Margin = new Padding(0, 0, 0, 10),
        };
        var beh = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 9,
            BackColor = Theme.Surface,
            Padding = new Padding(0),
        };
        for (int i = 0; i < 9; i++)
            beh.RowStyles.Add(new RowStyle(SizeType.Percent, 100f / 9f));

        StartupMode startupMode = StartupManager.GetMode();
        _lockOnRemoval = Toggle("Auto-lock when the key is removed", _config.Guard.LockOnRemoval);
        _balloonTips = Toggle("Balloon notifications on lock/unlock", _config.Guard.BalloonTips);
        _animations = Toggle("Interface animations", _config.Guard.Animations);
        _sounds = Toggle("Lock/unlock sound cues", _config.Guard.Sounds);
        _startup = Toggle("Start with Windows", startupMode != StartupMode.Off);
        _watchdog = Toggle("Watchdog process (auto-restart the guard)", _config.Guard.Watchdog);
        _lockPolicies = Toggle("Restrict Task Manager, sign-out & power while locked",
            _config.Guard.LockPolicies);
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
        beh.Controls.Add(_sounds);
        beh.Controls.Add(_startup);
        beh.Controls.Add(_watchdog);
        beh.Controls.Add(_lockPolicies);
        beh.Controls.Add(adminRow);
        beh.Controls.Add(pollRow);
        behCard.Controls.Add(beh);

        // ---- Unlock policy ----
        var policyCard = new CardPanel
        {
            Title = "Unlock policy",
            Glyph = Glyphs.Shield,
            Dock = DockStyle.Top,
            Height = 196,
            Margin = new Padding(0, 0, 0, 10),
        };
        var pol = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 4,
            BackColor = Theme.Surface,
            Padding = new Padding(0),
        };
        pol.RowStyles.Add(new RowStyle(SizeType.Percent, 30f));
        pol.RowStyles.Add(new RowStyle(SizeType.Percent, 22f));
        pol.RowStyles.Add(new RowStyle(SizeType.Percent, 22f));
        pol.RowStyles.Add(new RowStyle(SizeType.Percent, 26f));

        var segRow = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 4,
            RowCount = 1,
            BackColor = Theme.Surface,
            Margin = new Padding(0),
        };
        segRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 26f));
        for (int i = 0; i < 3; i++)
            segRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 74f / 3f));
        var segLabel = new Label
        {
            Text = "Unlock requires",
            Font = Theme.UIFont(9f),
            ForeColor = Theme.Text,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            AutoSize = false,
        };
        segRow.Controls.Add(segLabel, 0, 0);

        _policy = _config.Guard.UnlockPolicy;
        _policyBtns = new AppButton[3];
        string[] policyLabels = { "Key or passphrase", "Key + passphrase", "Key only" };
        for (int i = 0; i < 3; i++)
        {
            int idx = i;
            var b = new AppButton
            {
                Text = policyLabels[i],
                Dock = DockStyle.Fill,
                Margin = new Padding(3, 4, 3, 4),
            };
            b.Click += (_, _) => SetPolicy((UnlockPolicy)idx);
            _policyBtns[i] = b;
            segRow.Controls.Add(b, i + 1, 0);
        }
        RefreshPolicyButtons();

        _strictTamper = Toggle("Strict tamper — stale keyfiles never unlock",
            _config.Guard.StrictTamper);
        _strictTamper.CheckedChanged += (_, _) => Save();

        _privateDesktop = Toggle("Lock on a private desktop (stronger)",
            !_config.Guard.LockMode.Equals("overlay", StringComparison.OrdinalIgnoreCase));
        _privateDesktop.CheckedChanged += (_, _) =>
        {
            UpdatePolicyWarning();
            Save();
        };

        _policyWarn = new Label
        {
            Font = Theme.UIFont(8.5f),
            ForeColor = Theme.AccentAmber,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            AutoSize = false,
        };
        UpdatePolicyWarning();

        pol.Controls.Add(segRow, 0, 0);
        pol.Controls.Add(_strictTamper, 0, 1);
        pol.Controls.Add(_privateDesktop, 0, 2);
        pol.Controls.Add(_policyWarn, 0, 3);
        policyCard.Controls.Add(pol);

        // ---- Tripwires & alerts ----
        var tripCard = new CardPanel
        {
            Title = "Tripwires & alerts",
            Glyph = Glyphs.Warning,
            Dock = DockStyle.Top,
            Height = 176,
            Margin = new Padding(0, 0, 0, 10),
        };
        var trip = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 3,
            BackColor = Theme.Surface,
            Padding = new Padding(0),
        };
        for (int i = 0; i < 3; i++)
            trip.RowStyles.Add(new RowStyle(SizeType.Percent, 100f / 3f));

        var idleRow = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 3,
            RowCount = 1,
            BackColor = Theme.Surface,
            Margin = new Padding(0),
        };
        idleRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 34f));
        idleRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 46f));
        idleRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 20f));
        var idleLabel = new Label
        {
            Text = "Lock after idle",
            Font = Theme.UIFont(9f),
            ForeColor = Theme.Text,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            AutoSize = false,
        };
        _idle = new Slider
        {
            Minimum = 0,
            Maximum = 30,
            Step = 1,
            Value = Math.Clamp(_config.Guard.IdleLockMinutes, 0, 30),
            Dock = DockStyle.Fill,
            Margin = new Padding(6, 0, 6, 0),
        };
        _idleValue = new Label
        {
            Text = _idle.Value == 0 ? "off" : $"{_idle.Value} min",
            Font = Theme.MonoFont(8.5f),
            ForeColor = Theme.TextDim,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleRight,
            AutoSize = false,
        };
        idleRow.Controls.Add(idleLabel);
        idleRow.Controls.Add(_idle);
        idleRow.Controls.Add(_idleValue);

        _webcam = Toggle("Webcam snapshot on tamper events", _config.Guard.WebcamOnTamper);

        var alertRow = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 3,
            RowCount = 1,
            BackColor = Theme.Surface,
            Margin = new Padding(0),
        };
        alertRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 34f));
        alertRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 46f));
        alertRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 20f));
        var alertLabel = new Label
        {
            Text = "Alert webhook (ntfy.sh, …)",
            Font = Theme.UIFont(9f),
            ForeColor = Theme.Text,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            AutoSize = false,
        };
        _alertUrl = new TextField
        {
            Text = _config.Guard.AlertUrl,
            PlaceholderText = "https://ntfy.sh/my-cryptokey",
            Dock = DockStyle.Fill,
            Margin = new Padding(6, 4, 6, 4),
        };
        var testAlert = new AppButton
        {
            Text = "Send test",
            Glyph = Glyphs.Play,
            Variant = ButtonVariant.Ghost,
            Dock = DockStyle.Fill,
            Margin = new Padding(6, 4, 0, 4),
        };
        testAlert.Click += (_, _) => SendTestAlert();
        alertRow.Controls.Add(alertLabel);
        alertRow.Controls.Add(_alertUrl);
        alertRow.Controls.Add(testAlert);

        trip.Controls.Add(idleRow, 0, 0);
        trip.Controls.Add(_webcam, 0, 1);
        trip.Controls.Add(alertRow, 0, 2);
        tripCard.Controls.Add(trip);

        // ---- Storage ----
        var storeCard = new CardPanel
        {
            Title = "Storage",
            Glyph = Glyphs.Folder,
            Dock = DockStyle.Top,
            Height = 176,
        };
        var store = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 3,
            BackColor = Theme.Surface,
            Padding = new Padding(0),
        };
        store.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 72f));
        store.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 28f));
        for (int i = 0; i < 3; i++)
            store.RowStyles.Add(new RowStyle(SizeType.Percent, 33.33f));
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
            Glyph = ShortcutManager.Exists(ShortcutTarget.StartMenu) ? Glyphs.Close : Glyphs.Check,
            Variant = ButtonVariant.Ghost,
            Dock = DockStyle.Fill,
            Margin = new Padding(8, 0, 0, 0),
        };
        _shortcutBtn.Text = ShortcutManager.Exists(ShortcutTarget.StartMenu) ? "Remove" : "Create";
        _shortcutBtn.Click += (_, _) => ToggleShortcut(ShortcutTarget.StartMenu, _shortcutBtn);
        var desktopShortcutLabel = new Label
        {
            Text = "Desktop shortcut",
            Font = Theme.UIFont(9f),
            ForeColor = Theme.TextDim,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            AutoSize = false,
        };
        _desktopShortcutBtn = new AppButton
        {
            Glyph = ShortcutManager.Exists(ShortcutTarget.Desktop) ? Glyphs.Close : Glyphs.Check,
            Variant = ButtonVariant.Ghost,
            Dock = DockStyle.Fill,
            Margin = new Padding(8, 0, 0, 0),
        };
        _desktopShortcutBtn.Text = ShortcutManager.Exists(ShortcutTarget.Desktop) ? "Remove" : "Create";
        _desktopShortcutBtn.Click += (_, _) => ToggleShortcut(ShortcutTarget.Desktop, _desktopShortcutBtn);
        store.Controls.Add(shortcutLabel, 0, 1);
        store.Controls.Add(_shortcutBtn, 1, 1);
        store.Controls.Add(desktopShortcutLabel, 0, 2);
        store.Controls.Add(_desktopShortcutBtn, 1, 2);
        storeCard.Controls.Add(store);

        layout.Controls.Add(behCard, 0, 0);
        layout.Controls.Add(policyCard, 0, 1);
        layout.Controls.Add(tripCard, 0, 2);
        layout.Controls.Add(storeCard, 0, 3);
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
        _sounds.CheckedChanged += (_, _) => Save();
        _startup.CheckedChanged += (_, _) => ApplyStartupMode();
        _startupAdmin.CheckedChanged += (_, _) => ApplyStartupMode();
        _watchdog.CheckedChanged += (_, _) => Save();
        _lockPolicies.CheckedChanged += (_, _) => Save();
        _webcam.CheckedChanged += (_, _) => Save();
        _idle.ValueChanged += (_, _) =>
        {
            _idleValue.Text = _idle.Value == 0 ? "off" : $"{_idle.Value} min";
            _pollSave.Stop();
            _pollSave.Start();
        };
        _alertUrl.TextValueChanged += (_, _) => { _pollSave.Stop(); _pollSave.Start(); };
        _pollSave.Tick += (_, _) => { _pollSave.Stop(); Save(); };
        _poll.ValueChanged += (_, _) =>
        {
            _pollValue.Text = $"{_poll.Value} ms";
            _service.ApplyPollInterval(_poll.Value);
            _pollSave.Stop();
            _pollSave.Start();
        };
    }

    private void SetPolicy(UnlockPolicy policy)
    {
        _policy = policy;
        UpdatePolicyWarning();
        RefreshPolicyButtons();
        Save();
    }

    /// <summary>
    /// One amber line under the policy card that surfaces whichever warnings
    /// currently apply: the lockout risk of stricter unlock policies, and the
    /// escape hatch for the private-desktop lock.
    /// </summary>
    private void UpdatePolicyWarning()
    {
        var parts = new List<string>();
        if (_policy != UnlockPolicy.KeyOrPassphrase)
            parts.Add("Lost key under this policy is a real lockout — only the dev " +
                      "panic combo or Task Manager can recover.");
        if (_privateDesktop.Checked)
            parts.Add("Private desktop: if the screen ever strands blank, " +
                      "run cryptokey --release-desktop.");
        _policyWarn.Text = string.Join("  ", parts);
        _policyWarn.Visible = parts.Count > 0;
    }

    private void RefreshPolicyButtons()
    {
        for (int i = 0; i < _policyBtns.Length; i++)
            _policyBtns[i].Variant = i == (int)_policy
                ? ButtonVariant.Primary : ButtonVariant.Ghost;
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
                using (p)
                {
                    // WaitForExit's bool first — ExitCode throws on a still-
                    // running process (UAC left up >90s) and would strand the
                    // toggles in the requested state.
                    bool ok = p.WaitForExit(90000) && p.ExitCode == 0;
                    try { BeginInvoke(() => FinishElevatedStartup(ok, mode)); }
                    catch (Exception) { }
                }
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

    private void ToggleShortcut(ShortcutTarget target, AppButton btn)
    {
        string name = target == ShortcutTarget.Desktop ? "Desktop" : "Start Menu";
        try
        {
            bool create = !ShortcutManager.Exists(target);
            ShortcutManager.SetEnabled(target, create);
            btn.Text = create ? "Remove" : "Create";
            btn.Glyph = create ? Glyphs.Close : Glyphs.Check;
            _notify(create ? $"{name} shortcut created" : $"{name} shortcut removed", false);
        }
        catch (Exception ex)
        {
            _notify($"Shortcut failed: {ex.Message}", true);
        }
    }

    private void SendTestAlert()
    {
        string url = _alertUrl.Text.Trim();
        if (url.Length == 0)
        {
            _notify("Set an alert URL first.", true);
            return;
        }
        // Test the field value, not the saved config — a bad URL should fail
        // visibly NOW, not during an attack. Failures land in guard.log.
        AlertService.Send(url, "Test", "test alert — CryptoKey is armed", _service.Log);
        _notify("Test alert queued — check your endpoint (failures log to guard.log).", false);
    }

    private void RestartElevated()
    {
        try
        {
            var p = Process.Start(new ProcessStartInfo(Application.ExecutablePath, "--takeover")
            {
                UseShellExecute = true,
                Verb = "runas",
            });
            if (p == null)
                throw new InvalidOperationException("elevated instance did not start");
            // Give the child a beat to die on its own startup errors before we
            // release the mutex — a failed takeover would otherwise leave the
            // machine silently unguarded.
            if (p.WaitForExit(2500))
            {
                _notify($"Elevated launch failed (exit {p.ExitCode})", true);
                p.Dispose();
                return;
            }
            p.Dispose();
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
        _config.Guard.Sounds = _sounds.Checked;
        _config.Guard.PollIntervalMs = _poll.Value;
        _config.Guard.UnlockPolicy = _policy;
        _config.Guard.StrictTamper = _strictTamper.Checked;
        _config.Guard.LockMode = _privateDesktop.Checked ? "secure" : "overlay";
        _config.Guard.Watchdog = _watchdog.Checked;
        _config.Guard.LockPolicies = _lockPolicies.Checked;
        _config.Guard.IdleLockMinutes = _idle.Value;
        _config.Guard.WebcamOnTamper = _webcam.Checked;
        _config.Guard.AlertUrl = _alertUrl.Text.Trim();
        try
        {
            ConfigStore.Save(_config);
        }
        catch (Exception ex)
        {
            _notify($"Save failed: {ex.Message}", true);
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _pollSave.Stop();
            _pollSave.Dispose();
        }
        base.Dispose(disposing);
    }
}
