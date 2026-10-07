using Avalonia.Controls;
using Avalonia.Headless.XUnit;
using Avalonia.VisualTree;
using CryptoKey.Tests;
using Xunit;

namespace CryptoKey.Ui.Tests;

/// <summary>
/// The tray flyout's two faces: unlocked it is a status + control panel;
/// unsigned-with-account-possible it degrades to a sign-in card that
/// leaks nothing — no armed state, key presence, vault row, or mutator
/// affordances. Bound-but-unsigned still ARMS auto-lock, so the card
/// keeps a working "Lock now"; an explicit sign-out latches protection
/// off and drops it. Create account appears only where no record is bound.
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
    private static void BindLockedAccount(GuardClient client, bool signedOut = false)
    {
        var auth = new AuthService(new SupabaseConfig
        {
            ProjectUrl = "https://test.supabase.co",
            AnonKey = "test-anon-key-0123456789abcdef",
        }, null);
        KeyConfig cfg = TestDisk.NewConfig(TestDisk.RandomSecret());
        cfg.Account = AccountRecord.Create("user-1", "a@b.c", "pw-123456");
        cfg.Account.SignedOut = signedOut;
        auth.BindConfig(cfg);
        AuthService.SetCurrent(auth);
    }

    /// <summary>How many times the Set-up-a-key CTA ran the wizard hook.</summary>
    private static int _onboardingOpened;

    private static TrayFlyout Show(GuardClient client)
    {
        _onboardingOpened = 0;
        var f = new TrayFlyout(client, new FakeHost(), _ => { }, () => { },
            a => a(), _ => { }, () => _onboardingOpened++);
        f.ShowNear();
        Harness.Pump(TimeSpan.FromMilliseconds(80));
        return f;
    }

    private static IEnumerable<Button> Buttons(TrayFlyout f)
        => f.GetVisualDescendants().OfType<Button>();

    private static string Label(Button b)
        => string.Join("", b.GetVisualDescendants().OfType<TextBlock>().Select(t => t.Text));

    [AvaloniaFact]
    public void Bound_but_unsigned_is_an_armed_signin_card()
    {
        // H1: unsigned ≠ disarmed — a bound record still arms auto-lock.
        // The card is honest about it: "Sign in" head, real "Lock now".
        var (_, client, _) = Harness.Guard();
        BindLockedAccount(client);
        TrayFlyout f = Show(client);

        var visible = Buttons(f).Where(b => b.IsVisible).Select(Label).ToList();
        Assert.Contains(visible, l => l.Contains("Sign in"));
        Assert.Contains(visible, l => l.Contains("Lock now"));
        Assert.DoesNotContain(visible, l => l.Contains("Create account")
            || l.Contains("Pause") || l.Contains("Resume")
            || l.Contains("Open CryptoKey") || l.Contains("Mount") || l.Contains("Open"));

        var texts = f.GetVisualDescendants().OfType<TextBlock>()
            .Where(t => t.IsVisible).Select(t => t.Text).ToList();
        Assert.Contains("Sign in", texts);
        Assert.Contains(texts, t => t != null && t.Contains("still locks"));
        Assert.DoesNotContain(texts, t => t is "ARMED" or "PAUSED" or "UNLOCKED");
    }

    [AvaloniaFact]
    public void Explicit_signout_is_a_disarmed_signin_card()
    {
        // H1: the persisted SignedOut latch is the ONLY unsigned state
        // that disarms — its card says "Signed out" and hides Lock now.
        var (_, client, _) = Harness.Guard();
        BindLockedAccount(client, signedOut: true);
        TrayFlyout f = Show(client);

        var visible = Buttons(f).Where(b => b.IsVisible).Select(Label).ToList();
        Assert.Contains(visible, l => l.Contains("Sign in"));
        Assert.DoesNotContain(visible, l => l.Contains("Lock now")
            || l.Contains("Create account")
            || l.Contains("Pause") || l.Contains("Resume"));

        var texts = f.GetVisualDescendants().OfType<TextBlock>()
            .Where(t => t.IsVisible).Select(t => t.Text).ToList();
        Assert.Contains("Signed out", texts);
        Assert.DoesNotContain(texts, t => t is "ARMED" or "PAUSED" or "UNLOCKED");
    }

    [AvaloniaFact]
    public void Unbound_but_configured_shows_create_account()
    {
        var (_, client, _) = Harness.Guard();
        AuthService.SetCurrent(new AuthService(new SupabaseConfig
        {
            ProjectUrl = "https://test.supabase.co",
            AnonKey = "test-anon-key-0123456789abcdef",
        }, null)); // backend present, no record — Gating false, Configured true
        TrayFlyout f = Show(client);

        var visible = Buttons(f).Where(b => b.IsVisible).Select(Label).ToList();
        Assert.Contains(visible, l => l.Contains("Sign in"));
        Assert.Contains(visible, l => l.Contains("Create account"));
        Assert.DoesNotContain(visible, l => l.Contains("Lock now"));

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

    [AvaloniaFact]
    public void Unenrolled_shows_the_setup_cta_not_a_key_status()
    {
        var (_, client, cfg) = Harness.Guard(c =>
        {
            // Dormant: config present, no key bound.
            c.DeviceSerial = ""; c.SecretSalt = ""; c.SecretHash = "";
            c.PrevSecretHash = ""; c.RotationCount = 0; c.LastRotationUtc = null;
        });
        AuthService.SetCurrent(new AuthService(null, null)); // ungated
        TrayFlyout f = Show(client);

        var visible = Buttons(f).Where(b => b.IsVisible).Select(Label).ToList();
        Assert.Contains(visible, l => l.Contains("Set up a key"));
        Assert.Contains(visible, l => l.Contains("Lock now")); // manual lock still works
        Assert.DoesNotContain(visible, l => l.Contains("Pause")
            || l.Contains("Sign in") || l.Contains("Create account"));

        var texts = f.GetVisualDescendants().OfType<TextBlock>()
            .Where(t => t.IsVisible).Select(t => t.Text).ToList();
        Assert.Contains("NO KEY", texts);
        Assert.Contains(texts, t => t?.Contains("No key enrolled") == true);
        Assert.DoesNotContain(texts, t => t is "ARMED");

        // The CTA lands on the enroll wizard.
        Button setup = Buttons(f).First(b => Label(b).Contains("Set up a key"));
        setup.RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
        Assert.Equal(1, _onboardingOpened);
    }
}
