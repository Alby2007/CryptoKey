using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;

namespace CryptoKey.Ui;

/// <summary>Identity, signed updates, honest limits, and the CLI reference.</summary>
internal sealed class AboutPage : Page
{
    private readonly TextBlock _updStatus = Kit.Txt("", "body", "dim");
    private readonly Button _check;
    private readonly Button _apply;
    private bool _checking;

    public AboutPage(PageContext ctx) : base(ctx)
    {
        var key = new KeyVisual { Height = 120, Width = 280, State = KeyVisualState.Armed, ShowEngraving = true };
        var identity = new Border
        {
            Classes = { "card" },
            Padding = new Thickness(24),
            Child = new Grid
            {
                ColumnDefinitions = new ColumnDefinitions("Auto,*"),
                ColumnSpacing = 24,
                Children =
                {
                    key,
                    WithColumn(Kit.V(8,
                        Kit.Txt("CryptoKey", "h1"),
                        Kit.Txt("Turn a USB drive into a physical key for your computer. Pull it out — the " +
                                "screen locks. Put it back — you're in.", "body", "dim"),
                        Kit.Txt(ctx.Host.VersionText, "mono", "faint")), 1),
                },
            },
        };
        ((Control)((Grid)identity.Child!).Children[1]).VerticalAlignment = VerticalAlignment.Center;

        _check = Kit.Btn("Check now", IconData.Refresh, "", CheckNow);
        _apply = Kit.Btn("Install update", IconData.Download, "primary", Apply);
        var updates = Kit.Section("Updates", IconData.Download,
            "Releases are signed; every download is verified before it runs.",
            Kit.V(12, _updStatus, Kit.H(10, _check, _apply)));

        string[] limits =
        {
            "Ctrl+Alt+Del and the OS security screen can't be blocked by any app.",
            "An administrator who kills every CryptoKey process at once defeats the lock — it lands them at your OS sign-in at best.",
            "Elevated windows may resist the input block unless CryptoKey also runs as administrator.",
            "The On-Screen Keyboard can bypass the keyboard hook if it was opened first.",
            "A strong deterrent and convenience lock — not a replacement for BitLocker/FileVault and your OS password.",
        };
        var limitList = new StackPanel { Spacing = 8 };
        for (int i = 0; i < limits.Length; i++)
        {
            var row = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*"), ColumnSpacing = 10 };
            row.Children.Add(new Icon(i == limits.Length - 1 ? IconData.Warning : IconData.ChevronRight, 15)
            {
                Foreground = i == limits.Length - 1 ? Palette.Paused : Palette.TextFaint,
                VerticalAlignment = VerticalAlignment.Top,
                Margin = new Thickness(0, 2, 0, 0),
            });
            row.Children.Add(WithColumn(Kit.Txt(limits[i], "body", i == limits.Length - 1 ? "warn" : "dim"), 1));
            limitList.Children.Add(row);
        }
        var limitCard = Kit.Section("Know the limits", IconData.Warning, "Honest about what a user-mode lock can and can't do.",
            limitList);

        var cmds = new Border
        {
            Classes = { "well" },
            Child = Kit.Txt(
                "cryptokey                 launch this app\n" +
                "cryptokey enroll          register a USB drive (console)\n" +
                "cryptokey lock            lock now\n" +
                "cryptokey pause 15        pause auto-lock for 15 minutes\n" +
                "cryptokey resume          re-arm now\n" +
                "cryptokey status          live guard state\n" +
                "cryptokey open [page]     open the dashboard (home, vault, protection…)\n" +
                "cryptokey vault …         vault create / mount / unmount / status\n" +
                "cryptokey update          check for a new signed build\n" +
                "cryptokey --release-desktop   rescue a stranded private-desktop lock",
                "mono", "dim"),
        };
        var cmdCard = Kit.Section("Command line", IconData.Terminal, null, cmds);

        Content = Kit.PageScroll(Kit.V(16,
            Kit.PageHeader("About", "What CryptoKey is, how it updates, and where its limits are."),
            identity, updates, limitCard, cmdCard));
    }

    private static Control WithColumn(Control c, int col)
    {
        Grid.SetColumn(c, col);
        return c;
    }

    public override void Refresh()
    {
        // Any snapshot after a click means the check resolved — the pending
        // flag inside it is the answer.
        string? pending = Client.Snapshot.PendingUpdate;
        _checking = false;
        _apply.IsEnabled = pending != null;
        _check.IsEnabled = true;
        _updStatus.Text = pending != null
            ? $"Update available: {pending} — the signed release is verified on download."
            : "Up to date — nothing installs without you asking.";
        _updStatus.Foreground = pending != null ? Palette.Signal : Palette.TextDim;
    }

    private async void CheckNow()
    {
        _checking = true;
        _check.IsEnabled = false;
        _updStatus.Text = "Checking for updates…";
        // "ok checking" replies instantly; the result lands via the next snapshot.
        string reply = await Client.Dispatch("update check");
        if (!reply.StartsWith("ok", StringComparison.Ordinal))
        {
            _updStatus.Text = reply;
            _check.IsEnabled = true;
        }
        await Task.Delay(8000);
        if (_checking)
            Refresh();
    }

    private async void Apply()
    {
        string reply = await Client.Dispatch("update apply");
        if (RetryAfterAuth(reply, Apply))
            return;
        bool ok = reply.StartsWith("ok", StringComparison.Ordinal);
        Ctx.Toast(ok ? "Applying — the app restarts on the new build."
            : ReplyError(reply) ?? reply, !ok);
        Refresh();
    }
}
