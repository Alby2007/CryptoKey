using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Headless.XUnit;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.LogicalTree;
using Avalonia.VisualTree;
using CryptoKey.Tests;
using Xunit;

namespace CryptoKey.Ui.Tests;

/// <summary>
/// The unenroll surfaces: the Key page's phrase-verified, hold-gated
/// removal well; the dormant "no key" faces (Key page CTA, Home presenter
/// copy); and the wizard's welcome line for an existing-but-unenrolled
/// config.
/// </summary>
public class UnenrollUiTests : IDisposable
{
    public UnenrollUiTests()
    {
        AuthService.SetCurrent(null);
        TokenStore.Clear();
        AuthService.PendingStore.Clear();
        ThrottleStore.Clear();
    }

    public void Dispose()
    {
        AuthService.SetCurrent(null);
        TokenStore.Clear();
        AuthService.PendingStore.Clear();
        ThrottleStore.Clear();
    }

    private static IEnumerable<Button> Buttons(Visual root)
        => root.GetVisualDescendants().OfType<Button>();

    private static string Label(Button b)
        => string.Join("", b.GetVisualDescendants().OfType<TextBlock>().Select(t => t.Text));

    private static Point Center(Window w, Control c)
        => c.TranslatePoint(new Point(c.Bounds.Width / 2, c.Bounds.Height / 2), w)!.Value;

    private static Window Show(Control content)
    {
        var w = new Window { Width = 1100, Height = 800, Content = content };
        w.Show();
        Harness.Pump(TimeSpan.FromMilliseconds(200));
        return w;
    }

    /// <summary>A context whose "Set up a key" clicks are counted.</summary>
    private static PageContext TrackedContext(GuardClient client, out Func<int> onboarded)
    {
        int count = 0;
        PageContext b = Harness.Context(client);
        onboarded = () => count;
        return new PageContext
        {
            Client = b.Client, Host = b.Host, Navigate = b.Navigate, Owner = b.Owner,
            Toast = b.Toast, ShowAuth = b.ShowAuth,
            OpenOnboarding = () => count++,
        };
    }

    [AvaloniaFact]
    public void Key_page_shows_the_removal_well_with_phrase_and_hold()
    {
        var (svc, client, _) = Harness.Guard();
        using (svc)
        {
            var page = new KeyPage(Harness.Context(client));
            Window w = Show(page);

            Button remove = Buttons(page).First(b => Label(b).Contains("Remove key…"));
            remove.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            Harness.Pump(TimeSpan.FromMilliseconds(50));

            var hold = page.GetLogicalDescendants().OfType<HoldButton>().SingleOrDefault();
            Assert.NotNull(hold);
            Assert.True(hold!.IsEffectivelyVisible);
            Assert.Contains(page.GetLogicalDescendants().OfType<TextBox>(),
                t => t.Watermark == "Recovery phrase");
            w.Close();
        }
    }

    [AvaloniaFact]
    public void A_phrase_and_a_full_hold_remove_the_key()
    {
        var (svc, client, cfg) = Harness.Guard();
        using (svc)
        {
            var page = new KeyPage(Harness.Context(client));
            Window w = Show(page);
            Buttons(page).First(b => Label(b).Contains("Remove key…"))
                .RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            Harness.Pump(TimeSpan.FromMilliseconds(80)); // well opens + lays out
            TextBox phrase = page.GetLogicalDescendants().OfType<TextBox>()
                .First(t => t.Watermark == "Recovery phrase");
            phrase.Text = "passphrase-ok"; // TestDisk.NewConfig's credential

            HoldButton hold = page.GetLogicalDescendants().OfType<HoldButton>().Single();
            Point p = Center(w, hold);
            w.MouseDown(p, MouseButton.Left);
            Harness.Pump(TimeSpan.FromMilliseconds(1700)); // HoldTime = 1400ms
            w.MouseUp(p, MouseButton.Left);
            // PBKDF2 runs on a pool thread inside the engine hop.
            Harness.Pump(TimeSpan.FromMilliseconds(1500));

            Assert.False(cfg.Enrolled);
            Assert.Contains(page.GetVisualDescendants().OfType<TextBlock>(),
                t => t.Text == "No key enrolled — protection is off");
            w.Close();
        }
    }

    [AvaloniaFact]
    public void A_wrong_phrase_keeps_the_key_bound()
    {
        var (svc, client, cfg) = Harness.Guard();
        using (svc)
        {
            var page = new KeyPage(Harness.Context(client));
            Window w = Show(page);
            Buttons(page).First(b => Label(b).Contains("Remove key…"))
                .RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            Harness.Pump(TimeSpan.FromMilliseconds(80));
            page.GetLogicalDescendants().OfType<TextBox>()
                .First(t => t.Watermark == "Recovery phrase").Text = "nope";

            HoldButton hold = page.GetLogicalDescendants().OfType<HoldButton>().Single();
            Point p = Center(w, hold);
            w.MouseDown(p, MouseButton.Left);
            Harness.Pump(TimeSpan.FromMilliseconds(1700));
            w.MouseUp(p, MouseButton.Left);
            Harness.Pump(TimeSpan.FromMilliseconds(1500));

            Assert.True(cfg.Enrolled);
            w.Close();
        }
    }

    [AvaloniaFact]
    public void Unenrolled_key_page_shows_the_setup_cta_not_the_removal_row()
    {
        var (svc, client, _) = Harness.Guard(c =>
        {
            c.DeviceSerial = ""; c.SecretSalt = ""; c.SecretHash = "";
            c.PrevSecretHash = ""; c.RotationCount = 0; c.LastRotationUtc = null;
        });
        using (svc)
        {
            var page = new KeyPage(TrackedContext(client, out Func<int> onboarded));
            Window w = Show(page);

            var texts = page.GetVisualDescendants().OfType<TextBlock>()
                .Where(t => t.IsEffectivelyVisible).Select(t => t.Text).ToList();
            Assert.Contains("No key enrolled — protection is off", texts);
            // Nothing to remove — the dangerous affordance isn't rendered.
            Assert.DoesNotContain(Buttons(page).Where(b => b.IsEffectivelyVisible),
                b => Label(b).Contains("Remove key"));

            Button setup = Buttons(page).First(b => Label(b).Contains("Set up a key"));
            setup.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            Assert.Equal(1, onboarded());
            w.Close();
        }
    }

    [AvaloniaFact]
    public void Home_presenter_dormant_copy_is_not_key_absent()
    {
        var s = new StatusSnapshot(GuardState.Unlocked, false, null, null, null,
            null, false, false, Enrolled: false);
        HomeView v = HomePresenter.Present(s,
            new SettingsView(new GuardSettings(), "", 0), devMode: false, elevated: false);

        Assert.Equal("NO KEY", v.StateWord);
        Assert.Contains("auto-lock", v.Reason);
        Assert.Equal(KeyVisualState.Absent, v.Visual);
        Assert.Equal("No key enrolled", v.KeyTitle);
        Assert.False(v.CanPause);   // nothing to pause
        Assert.True(v.CanLock);     // manual lock still works
        Assert.Contains(v.Chips, c => c.Text == "no key enrolled");

        // Locked while unenrolled: the phrase is the only way back.
        var locked = new StatusSnapshot(GuardState.Locked, false, null, null, null,
            null, false, false, Enrolled: false);
        Assert.Contains("recovery phrase",
            HomePresenter.Present(locked,
                new SettingsView(new GuardSettings(), "", 0), false, false).Reason);
    }

    [AvaloniaFact]
    public void Wizard_welcomes_a_dormant_config_like_a_fresh_one()
    {
        // An existing-but-unenrolled config must not read "replaces the key".
        KeyConfig cfg = TestDisk.NewConfig(TestDisk.RandomSecret());
        cfg.DeviceSerial = ""; cfg.SecretSalt = ""; cfg.SecretHash = "";
        ConfigStore.Save(cfg);
        var w = new OnboardingWindow(new FakeHost(), firstRun: false,
            (_, _) => Task.FromResult(new EnrollResult(false, "", null, null, [])));
        w.Show();
        Harness.Pump(TimeSpan.FromMilliseconds(150));
        Assert.Contains(w.GetVisualDescendants().OfType<TextBlock>(),
            t => t.Text == "Register a drive as your key.");
        w.Close();
    }
}
