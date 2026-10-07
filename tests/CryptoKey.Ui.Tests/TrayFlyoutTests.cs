using Avalonia.Controls;
using Avalonia.Headless.XUnit;
using Avalonia.VisualTree;
using CryptoKey.Tests;
using Xunit;

namespace CryptoKey.Ui.Tests;

/// <summary>
/// The tray flyout's two faces: unlocked it is a status + control panel;
/// gated-out it must degrade to a sign-in card that leaks nothing — no
/// armed state, key presence, vault row, or mutator affordances — while
/// keeping Lock now (always safe) and the sign-in call to action.
/// </summary>
public class TrayFlyoutTests : IDisposable
{
    public TrayFlyoutTests()
    {
        AuthService.SetCurrent(null);
        TokenStore.Clear();
        AuthService.PendingStore.Clear();
    }

    public void Dispose()
    {
        AuthService.SetCurrent(null);
        TokenStore.Clear();
        AuthService.PendingStore.Clear();
    }

    /// <summary>An account-bound install with no session: Gating, not Authorized.</summary>
    private static void BindLockedAccount(GuardClient client)
    {
        var auth = new AuthService(new SupabaseConfig
        {
            ProjectUrl = "https://test.supabase.co",
            AnonKey = "test-anon-key-0123456789abcdef",
        }, null);
        KeyConfig cfg = TestDisk.NewConfig(TestDisk.RandomSecret());
        cfg.Account = AccountRecord.Create("user-1", "a@b.c", "pw-123456");
        auth.BindConfig(cfg);
        AuthService.SetCurrent(auth);
    }

    private static TrayFlyout Show(GuardClient client)
    {
        var f = new TrayFlyout(client, new FakeHost(), _ => { }, () => { }, a => a());
        f.ShowNear();
        Harness.Pump(TimeSpan.FromMilliseconds(80));
        return f;
    }

    private static IEnumerable<Button> Buttons(TrayFlyout f)
        => f.GetVisualDescendants().OfType<Button>();

    private static string Label(Button b)
        => string.Join("", b.GetVisualDescendants().OfType<TextBlock>().Select(t => t.Text));

    [AvaloniaFact]
    public void Locked_variant_is_a_signin_card_not_a_status_panel()
    {
        var (_, client, _) = Harness.Guard();
        BindLockedAccount(client);
        TrayFlyout f = Show(client);

        var visible = Buttons(f).Where(b => b.IsVisible).Select(Label).ToList();
        Assert.Contains(visible, l => l.Contains("Lock now"));
        Assert.Contains(visible, l => l.Contains("Sign in"));
        Assert.DoesNotContain(visible, l => l.Contains("Pause") || l.Contains("Resume")
            || l.Contains("Open CryptoKey") || l.Contains("Mount") || l.Contains("Open"));

        // The masked head: no real state word leaks — "Signed out".
        var texts = f.GetVisualDescendants().OfType<TextBlock>()
            .Where(t => t.IsVisible).Select(t => t.Text).ToList();
        Assert.Contains("Signed out", texts);
        Assert.DoesNotContain(texts, t => t is "ARMED" or "PAUSED" or "UNLOCKED");
    }

    [AvaloniaFact]
    public void Ungated_install_renders_the_full_panel()
    {
        var (_, client, _) = Harness.Guard();
        AuthService.SetCurrent(new AuthService(null, null)); // no backend — not gating
        TrayFlyout f = Show(client);

        var visible = Buttons(f).Where(b => b.IsVisible).Select(Label).ToList();
        Assert.Contains(visible, l => l.Contains("Lock now"));
        Assert.Contains(visible, l => l.Contains("Open CryptoKey"));
        Assert.DoesNotContain(visible, l => l.Contains("Sign in"));
    }
}
