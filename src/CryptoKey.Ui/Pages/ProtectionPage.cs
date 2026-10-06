using Avalonia;
using Avalonia.Controls;
using Avalonia.Threading;

namespace CryptoKey.Ui;

/// <summary>
/// Protection: what locks the machine, what unlocks it, and how hard the
/// lock fights back. Every toggle writes through <see cref="GuardClient.UpdateSettings"/>.
/// </summary>
internal sealed class ProtectionPage : Page
{
    private readonly ToggleSwitch _lockOnRemoval;
    private readonly Slider _idle = new() { Minimum = 0, Maximum = 30, SmallChange = 1, TickFrequency = 1, IsSnapToTickEnabled = true, Width = 220 };
    private readonly TextBlock _idleText = Kit.Txt("", "mono", "dim");
    private readonly Segmented _policy;
    private readonly TextBlock _policyHelp = Kit.Txt("", "caption", "dim");
    private readonly Banner _warn = new();
    private readonly ToggleSwitch _privateDesktop;
    private readonly ToggleSwitch _strict;
    private readonly ToggleSwitch _lockPolicies;
    private readonly ToggleSwitch _watchdog;
    private readonly ToggleSwitch _admin;
    private readonly TextBlock _adminHint = Kit.Txt("", "caption", "faint");
    private readonly TextBlock _elevation = Kit.Txt("", "caption");
    private readonly Button _restartAdmin;
    private readonly Slider _poll = new() { Minimum = 250, Maximum = 10000, SmallChange = 250, TickFrequency = 250, IsSnapToTickEnabled = true, Width = 220 };
    private readonly TextBlock _pollText = Kit.Txt("", "mono", "dim");
    private readonly DispatcherTimer _debounce = new() { Interval = TimeSpan.FromMilliseconds(450) };
    private bool _syncing;

    public ProtectionPage(PageContext ctx) : base(ctx)
    {
        PlatformCapabilities caps = ctx.Caps;
        _lockOnRemoval = Kit.Toggle(false, on => Set(g => g.LockOnRemoval = on));
        _idle.ValueChanged += (_, _) => { _idleText.Text = ProtectionPresenter.IdleText((int)_idle.Value); Debounce(_idle); };
        _poll.ValueChanged += (_, _) => { _pollText.Text = $"{(int)_poll.Value} ms"; Debounce(_poll); };
        _debounce.Tick += (_, _) =>
        {
            _debounce.Stop();
            int idle = (int)_idle.Value, poll = (int)_poll.Value;
            Save(g => { g.IdleLockMinutes = idle; g.PollIntervalMs = poll; });
        };

        _policy = new Segmented(ProtectionPresenter.Policies.Select(p => p.Label).ToArray());
        _policy.SelectionChanged += i => Set(g => g.UnlockPolicy = ProtectionPresenter.Policies[i].Policy);

        _privateDesktop = Kit.Toggle(false, on => Set(g => g.LockMode = on ? "secure" : "overlay"));
        _strict = Kit.Toggle(false, on => Set(g => g.StrictTamper = on));
        _lockPolicies = Kit.Toggle(false, on => Set(g => g.LockPolicies = on));
        _watchdog = Kit.Toggle(false, on => Set(g => g.Watchdog = on));
        _admin = Kit.Toggle(false, on => { if (!_syncing) ApplyAdmin(on); });
        _restartAdmin = Kit.Btn("Restart as administrator", IconData.Admin, "small", RestartElevated);

        var triggers = Kit.Section("Lock triggers", IconData.Zap, "What locks this machine.",
            Kit.Row("Lock when the key is removed",
                "Off = manual-lock only (tray, Home, or the CLI).", _lockOnRemoval),
            Kit.Row("Lock after idle", "No keyboard or mouse input for this long.", Kit.H(12, _idle, _idleText)));

        var unlock = Kit.Section("Unlock policy", IconData.Key, "What it takes to get back in.",
            Kit.V(10, _policy, _policyHelp, _warn));
        unlock.Margin = new Thickness(0);

        var hardening = Kit.Section("Hardening", IconData.Shield, "How hard the lock fights back.",
            Kit.Gate(Kit.Row("Lock on a private desktop",
                "Stronger: the lock runs on its own desktop, out of reach of other windows.", _privateDesktop),
                caps.PrivateDesktop, caps.Unavailable),
            Kit.Row("Strict tamper", "Stale (previous-generation) keyfiles never unlock.", _strict),
            Kit.Gate(Kit.Row("Restrict Task Manager, sign-out & power",
                "Applied only while locked; needs administrator rights on most machines.", _lockPolicies),
                caps.LockPolicies, caps.Unavailable),
            Kit.Row("Watchdog process", "A supervisor restarts the guard if it's killed.", _watchdog),
            Kit.Gate(Kit.V(0,
                Kit.Row("Start as administrator at login",
                    "Stronger lock: policies apply and elevated windows can't dodge the input block.", _admin),
                _adminHint),
                caps.Elevation, caps.Unavailable),
            Kit.Gate(Kit.Row("Current session", null, Kit.H(12, _elevation, _restartAdmin)),
                caps.Elevation, caps.Unavailable));

        var detection = Kit.Section("Detection", IconData.Scan, null,
            Kit.Row("USB poll interval", "Backup check alongside device-change events.", Kit.H(12, _poll, _pollText)));

        var limits = new Banner();
        limits.Set("CryptoKey is a strong deterrent, not an OS security boundary — Ctrl+Alt+Del, an " +
                   "administrator killing every CryptoKey process, or a firmware-level attack are out of reach " +
                   "for any user-mode lock. Pair it with BitLocker/FileVault and your OS password.", Tone.Neutral);

        Content = Kit.PageScroll(Kit.V(16,
            Kit.PageHeader("Protection", "What locks this machine, what unlocks it, and how hard the lock fights back."),
            triggers, unlock, hardening, detection, limits));
    }

    private void Set(Action<GuardSettings> mutate)
    {
        if (!_syncing)
            Save(mutate);
    }

    private void Debounce(Control source)
    {
        if (_syncing || !Kit.UserDriven(source))
            return;
        _debounce.Stop();
        _debounce.Start();
    }

    public override void Refresh()
    {
        GuardSettings g = G;
        _syncing = true;
        try
        {
            _lockOnRemoval.IsChecked = g.LockOnRemoval;
            if (!_debounce.IsEnabled) // don't yank a slider mid-drag
            {
                _idle.Value = Math.Clamp(g.IdleLockMinutes, 0, 30);
                _idleText.Text = ProtectionPresenter.IdleText(g.IdleLockMinutes);
                _poll.Value = Math.Clamp(g.PollIntervalMs, 250, 10000);
                _pollText.Text = $"{g.PollIntervalMs} ms";
            }
            int idx = Array.FindIndex(ProtectionPresenter.Policies, p => p.Policy == g.UnlockPolicy);
            _policy.SelectedIndex = Math.Max(0, idx);
            _policyHelp.Text = ProtectionPresenter.Policies[Math.Max(0, idx)].Help;
            bool secure = !g.LockMode.Equals("overlay", StringComparison.OrdinalIgnoreCase);
            _privateDesktop.IsChecked = secure;
            var warnings = ProtectionPresenter.Warnings(g.UnlockPolicy, secure && Ctx.Caps.PrivateDesktop);
            _warn.IsVisible = warnings.Count > 0;
            _warn.Set(string.Join("\n", warnings), Tone.Warn);
            _strict.IsChecked = g.StrictTamper;
            _lockPolicies.IsChecked = g.LockPolicies;
            _watchdog.IsChecked = g.Watchdog;
            SyncStartup();
        }
        finally
        {
            _syncing = false;
        }
    }

    private void SyncStartup()
    {
        if (!Ctx.Caps.Elevation)
            return;
        UiStartupMode mode = Ctx.Host.GetStartupMode();
        bool wasSyncing = _syncing;
        _syncing = true;
        _admin.IsChecked = mode == UiStartupMode.Elevated;
        _admin.IsEnabled = mode != UiStartupMode.Off;
        _adminHint.Text = mode == UiStartupMode.Off ? "Turn on “Start at login” in General first." : "";
        _adminHint.IsVisible = mode == UiStartupMode.Off;
        bool elevated = Ctx.Host.IsElevated;
        _elevation.Text = elevated ? "Running as administrator" : "Running without administrator rights";
        _elevation.Foreground = elevated ? Palette.Armed : Palette.Paused;
        _restartAdmin.IsVisible = !elevated;
        _syncing = wasSyncing;
    }

    private async void ApplyAdmin(bool on)
    {
        UiStartupMode target = on ? UiStartupMode.Elevated
            : Ctx.Host.GetStartupMode() == UiStartupMode.Off ? UiStartupMode.Off : UiStartupMode.Normal;
        string? err = await Ctx.Host.SetStartupModeAsync(target, msg => Ctx.Toast(msg, false));
        Report(err, StartupText(target));
        SyncStartup();
    }

    internal static string StartupText(UiStartupMode m) => m switch
    {
        UiStartupMode.Elevated => "Starts at login as administrator",
        UiStartupMode.Normal => "CryptoKey will start at login",
        _ => "Removed from login startup",
    };

    private void RestartElevated()
    {
        string? err = Ctx.Host.StartElevatedInstance();
        if (err != null)
        {
            Ctx.Toast(err, true);
            return;
        }
        // The elevated --takeover instance parks on the guard mutex; exiting
        // hands it over with no unguarded gap.
        Client.Exit();
    }

    protected override void OnHidden() => _debounce.Stop();
}
