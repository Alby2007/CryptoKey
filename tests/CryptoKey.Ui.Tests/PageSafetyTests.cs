using System.Text.Json;
using Avalonia.Controls;
using Avalonia.Headless.XUnit;
using Xunit;

namespace CryptoKey.Ui.Tests;

/// <summary>
/// Merely LOOKING at a page must never change anything. Two real bugs
/// broke this: auto-firing hold buttons (vault reformat/delete) and a combo
/// box whose init-time selection event rewrote the vault drive letter.
/// Every page is opened, left to settle with real timers, and the config
/// must come out byte-identical. Doubles as a render smoke test at the
/// smallest, default and a large window size.
/// </summary>
public class PageSafetyTests
{
    private static readonly Func<PageContext, Page>[] Pages =
    {
        c => new HomePage(c),
        c => new KeyPage(c),
        c => new VaultPage(c),
        c => new ProtectionPage(c),
        c => new AlertsPage(c),
        c => new ActivityPage(c),
        c => new GeneralPage(c),
        c => new AboutPage(c),
    };

    [AvaloniaTheory]
    [InlineData(620, 560)]
    [InlineData(860, 700)]
    [InlineData(1400, 1000)]
    public void Opening_every_page_changes_nothing(double width, double height)
    {
        (GuardService svc, GuardClient client, KeyConfig cfg) = Harness.Guard();
        using (svc)
        {
            cfg.Guard.VaultMountPoint = "V:";
            cfg.Guard.PollIntervalMs = 1000;
            string before = JsonSerializer.Serialize(cfg);
            var host = new FakeHost { Startup = UiStartupMode.Normal };
            int toasts = 0;
            PageContext ctx = Harness.Context(client, host) is var c
                ? new PageContext
                {
                    Client = c.Client, Host = c.Host, Navigate = c.Navigate, Owner = c.Owner,
                    OpenOnboarding = c.OpenOnboarding, Toast = (_, _) => toasts++,
                }
                : throw new InvalidOperationException();

            foreach (Func<PageContext, Page> make in Pages)
            {
                Page page = make(ctx);
                var w = new Window { Width = width, Height = height, Content = page };
                w.Show();
                Harness.Pump(TimeSpan.FromMilliseconds(900));
                w.Close();
                Harness.Pump(TimeSpan.FromMilliseconds(50));
            }

            Assert.Equal(before, JsonSerializer.Serialize(cfg));
            Assert.Equal(UiStartupMode.Normal, host.Startup);
            Assert.Equal(0, toasts);
        }
    }
}
