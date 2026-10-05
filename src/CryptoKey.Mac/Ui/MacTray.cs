using Avalonia;
using Avalonia.Controls;
using Avalonia.Threading;

namespace CryptoKey;

/// <summary>
/// Menu-bar presence for the running guard — the only always-on UI. Menu
/// verbs go through the same dispatch table the IPC pipe uses, so the tray
/// and `cryptokey lock|pause|resume|quit` are one code path.
/// </summary>
internal static class MacTray
{
    public static TrayIcon Install(GuardService svc)
    {
        var menu = new NativeMenu();

        menu.Items.Add(Verb("Lock now", "lock", svc));
        menu.Items.Add(Verb("Pause 5 min", "pause", svc));
        menu.Items.Add(Verb("Resume", "resume", svc));
        menu.Items.Add(new NativeMenuItemSeparator());
        menu.Items.Add(Verb("Status…", "status", svc));
        menu.Items.Add(new NativeMenuItemSeparator());
        menu.Items.Add(Verb("Quit CryptoKey", "quit", svc));

        var tray = new TrayIcon
        {
            Icon = LoadIcon(),
            ToolTipText = "CryptoKey — USB security key",
            Menu = menu,
        };
        TrayIcon.SetIcons(Application.Current!, new TrayIcons { tray });
        return tray;
    }

    private static NativeMenuItem Verb(string label, string verb, GuardService svc)
    {
        var item = new NativeMenuItem(label);
        item.Click += (_, _) =>
        {
            // Dispatch on the UI thread — same affinity the pipe gives it.
            Dispatcher.UIThread.Post(() =>
            {
                string reply = svc.DispatchCommand(verb);
                if (reply.StartsWith("err", StringComparison.Ordinal)
                    || verb == "status")
                {
                    // Errors always surface; Status is the menu's only
                    // read-only verb — show the snapshot it returned.
                    Platform.Services.UserAlerts.Warn(
                        reply.StartsWith("ok ", StringComparison.Ordinal)
                            ? reply[3..]
                            : reply);
                }
            });
        };
        return item;
    }

    private static WindowIcon LoadIcon()
    {
        var asm = typeof(MacTray).Assembly;
        string name = asm.GetManifestResourceNames()
            .First(n => n.EndsWith("tray.png", StringComparison.Ordinal));
        using var stream = asm.GetManifestResourceStream(name)!;
        return new WindowIcon(stream);
    }
}
