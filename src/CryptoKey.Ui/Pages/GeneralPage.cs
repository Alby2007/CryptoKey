using Avalonia.Controls;

namespace CryptoKey.Ui;

/// <summary>General: startup, shortcuts, motion, updates, storage.</summary>
internal sealed class GeneralPage : Page
{
    private readonly ToggleSwitch _startup;
    private readonly ToggleSwitch _animations;
    private readonly ToggleSwitch _updates;
    private readonly Button _startMenu;
    private readonly Button _desktop;
    private bool _syncing;

    public GeneralPage(PageContext ctx) : base(ctx)
    {
        PlatformCapabilities caps = ctx.Caps;
        _startup = Kit.Toggle(false, on => { if (!_syncing) ApplyStartup(on); });
        _animations = Kit.Toggle(true, on =>
        {
            if (_syncing)
                return;
            Motion.SetSetting(on);
            Save(g => g.Animations = on);
        });
        _updates = Kit.Toggle(true, on => { if (!_syncing) Save(g => g.UpdateCheckEnabled = on); });
        _startMenu = Kit.Btn("Create", IconData.Check, "small", () => ToggleShortcut(UiShortcut.StartMenu));
        _desktop = Kit.Btn("Create", IconData.Check, "small", () => ToggleShortcut(UiShortcut.Desktop));

        var startup = Kit.Section("Startup", IconData.Power, null,
            Kit.Gate(Kit.Row($"Start at login",
                "The guard starts with your session. Administrator mode lives under Protection.", _startup),
                caps.StartupAtLogin, caps.Unavailable));

        var shell = Kit.Section("Shortcuts", IconData.Link, null,
            Kit.Gate(Kit.Row("Start Menu shortcut", null, _startMenu), caps.Shortcuts, caps.Unavailable),
            Kit.Gate(Kit.Row("Desktop shortcut", null, _desktop), caps.Shortcuts, caps.Unavailable));

        var look = Kit.Section("Appearance", IconData.Sparkles, null,
            Kit.Row("Interface animations",
                "Key motion, transitions and pulses. Your OS reduced-motion setting is always honored.", _animations));

        var updates = Kit.Section("Updates", IconData.Download, null,
            Kit.Row("Check for updates", "Signed releases, checked daily. Nothing installs without you asking.", _updates),
            Kit.Row("Update now", null, Kit.Btn("Go to About", IconData.ArrowRight, "ghost small", () => Ctx.Navigate(Route.About))));

        var storage = Kit.Section("Storage", IconData.Drive, null,
            Kit.Row("Configuration & logs", ConfigStore.ConfigDir,
                Kit.Btn("Open folder", IconData.Folder, "small", () => Ctx.Host.OpenFolder(ConfigStore.ConfigDir))));

        Content = Kit.PageScroll(Kit.V(16,
            Kit.PageHeader("General", "Startup, shortcuts, appearance and updates."),
            startup, shell, look, updates, storage));
    }

    public override void Refresh()
    {
        _syncing = true;
        try
        {
            _animations.IsChecked = G.Animations;
            _updates.IsChecked = G.UpdateCheckEnabled;
            if (Ctx.Caps.StartupAtLogin)
                _startup.IsChecked = Ctx.Host.GetStartupMode() != UiStartupMode.Off;
            if (Ctx.Caps.Shortcuts)
            {
                SetShortcutLabel(_startMenu, Ctx.Host.ShortcutExists(UiShortcut.StartMenu));
                SetShortcutLabel(_desktop, Ctx.Host.ShortcutExists(UiShortcut.Desktop));
            }
        }
        finally
        {
            _syncing = false;
        }
    }

    private static void SetShortcutLabel(Button b, bool exists)
        => Kit.SetLabel(b, exists ? "Remove" : "Create", exists ? IconData.Close : IconData.Check);

    private async void ApplyStartup(bool on)
    {
        UiStartupMode current = Ctx.Host.GetStartupMode();
        UiStartupMode target = !on ? UiStartupMode.Off
            : current == UiStartupMode.Elevated ? UiStartupMode.Elevated : UiStartupMode.Normal;
        string? err = await Ctx.Host.SetStartupModeAsync(target, m => Ctx.Toast(m, false));
        Report(err, ProtectionPage.StartupText(target));
        Refresh();
    }

    private void ToggleShortcut(UiShortcut which)
    {
        string name = which == UiShortcut.Desktop ? "Desktop" : "Start Menu";
        try
        {
            bool create = !Ctx.Host.ShortcutExists(which);
            Ctx.Host.SetShortcut(which, create);
            Ctx.Toast(create ? $"{name} shortcut created" : $"{name} shortcut removed", false);
        }
        catch (Exception ex)
        {
            Ctx.Toast($"Shortcut failed: {ex.Message}", true);
        }
        Refresh();
    }
}
