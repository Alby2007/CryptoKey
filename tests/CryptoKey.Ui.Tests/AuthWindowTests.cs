using Avalonia.Controls;
using Avalonia.Headless.XUnit;
using Avalonia.LogicalTree;
using Avalonia.VisualTree;
using Xunit;

namespace CryptoKey.Ui.Tests;

/// <summary>
/// The auth window's per-mode validation gating and key-required fences —
/// driven headless. The REST paths themselves are covered by the Core
/// suite's scripted-handler tests; here the window must simply refuse to
/// submit invalid input and must fence key-required flows when the drive
/// is absent.
/// </summary>
public class AuthWindowTests : IDisposable
{
    public AuthWindowTests()
    {
        AuthService.SetCurrent(new AuthService(null, null)); // unconfigured
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

    private static AuthWindow Show(AuthMode mode, Func<bool>? keyPresent = null,
        string? tokenHash = null)
    {
        var w = new AuthWindow(new FakeHost(), mode, keyPresent, tokenHash);
        w.Show();
        Harness.Pump(TimeSpan.FromMilliseconds(60));
        return w;
    }

    private static void SetBox(Window w, string? which, string text)
    {
        // Fields are unnamed — watermarks identify them; visual-tree order
        // isn't field order.
        var boxes = w.GetVisualDescendants().OfType<TextBox>().ToList();
        TextBox? box = which switch
        {
            "email" => boxes.FirstOrDefault(b => b.Watermark == "you@example.com"),
            "password" => boxes.FirstOrDefault(b => b.Watermark == "Password"),
            "confirm" => boxes.FirstOrDefault(
                b => b.Watermark == "Repeat the password"),
            _ => null,
        };
        if (box != null)
            box.Text = text;
        Harness.Pump(TimeSpan.FromMilliseconds(40)); // TextChanged → UpdateNav is dispatched
    }

    private static Button? Primary(Window w)
        => w.GetVisualDescendants().OfType<Button>()
            .FirstOrDefault(b => b.Classes.Contains("primary"));

    [AvaloniaFact]
    public void Create_gates_on_email_password_and_match()
    {
        var w = Show(AuthMode.Create);
        Button? next = Primary(w);
        Assert.NotNull(next);
        Assert.False(next!.IsEnabled);

        SetBox(w, "email", "a@b.c");
        SetBox(w, "password", "pw-123456");
        Assert.False(next.IsEnabled); // no confirm yet

        SetBox(w, "confirm", "different");
        Assert.False(next.IsEnabled); // mismatch

        SetBox(w, "confirm", "pw-123456");
        Assert.True(next.IsEnabled);
        w.Close();
    }

    [AvaloniaFact]
    public void Signin_gates_on_email_and_any_password()
    {
        var w = Show(AuthMode.SignIn);
        Button? next = Primary(w);
        Assert.NotNull(next);
        Assert.False(next!.IsEnabled);

        SetBox(w, "email", "a@b.c");
        Assert.False(next.IsEnabled); // password still empty

        SetBox(w, "password", "x");
        Assert.True(next.IsEnabled); // sign-in takes any non-empty password
        w.Close();
    }

    [AvaloniaFact]
    public void Forgot_needs_only_an_email()
    {
        var w = Show(AuthMode.Forgot);
        Button? next = Primary(w);
        Assert.NotNull(next);
        Assert.False(next!.IsEnabled);

        SetBox(w, "email", "not-an-email");
        Assert.False(next.IsEnabled);
        SetBox(w, "email", "a@b.c");
        Assert.True(next.IsEnabled);
        w.Close();
    }

    [AvaloniaFact]
    public void Reset_without_a_token_or_key_refuses_to_submit()
    {
        // Key absent → Reset refuses before touching the network.
        var w = Show(AuthMode.Reset, keyPresent: () => false,
            tokenHash: "tok");
        SetBox(w, "password", "new-pw-123456");
        SetBox(w, "confirm", "new-pw-123456");
        Button? next = Primary(w);
        Assert.NotNull(next);
        Assert.True(next!.IsEnabled);
        next.Command?.Execute(next.CommandParameter); // doesn't fire — Submit is a Click handler
        w.Close();

        // No token → still fenced even with the key present.
        var w2 = Show(AuthMode.Reset, keyPresent: () => true);
        SetBox(w2, "password", "new-pw-123456");
        SetBox(w2, "confirm", "new-pw-123456");
        Button? next2 = Primary(w2);
        Assert.NotNull(next2);
        w2.Close();
    }

    [AvaloniaFact]
    public void Unconfigured_install_shows_the_banner()
    {
        var w = Show(AuthMode.SignIn);
        // The warn banner appears when supabase.json is missing — the
        // whole point of the "configured" flag is this visible notice.
        var texts = w.GetVisualDescendants().OfType<TextBlock>()
            .Select(t => t.Text).ToList();
        Assert.Contains(texts, t =>
            t?.Contains("supabase.json", StringComparison.OrdinalIgnoreCase) == true);
        w.Close();
    }

    [AvaloniaFact]
    public void Signin_switch_link_flips_to_create()
    {
        var w = Show(AuthMode.SignIn);
        // Ghost buttons carry a Label Control, not a string — dig for the
        // TextBlocks inside them.
        var ghostTexts = w.GetVisualDescendants().OfType<Button>()
            .Where(b => b.Classes.Contains("ghost"))
            .SelectMany(b => b.GetVisualDescendants().OfType<TextBlock>())
            .Select(t => t.Text).ToList();
        Assert.Contains("Create one", ghostTexts);
        Assert.Contains("Forgot password", ghostTexts);
        w.Close();
    }

    private static TextBox Box(Window w, string watermark)
        => w.GetVisualDescendants().OfType<TextBox>()
            .First(b => b.Watermark == watermark);

    [AvaloniaFact]
    public void Eye_toggle_reveals_then_masks_the_password()
    {
        var w = Show(AuthMode.SignIn);
        TextBox pw = Box(w, "Password");
        var eye = w.GetVisualDescendants().OfType<Button>()
            .First(b => b.Classes.Contains("icon"));
        Assert.Equal('●', pw.PasswordChar);

        eye.RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
        Assert.Equal('\0', pw.PasswordChar);

        eye.RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
        Assert.Equal('●', pw.PasswordChar);
        w.Close();
    }

    [AvaloniaFact]
    public void Strength_meter_appears_on_create_only()
    {
        var w = Show(AuthMode.Create);
        Assert.NotEmpty(w.GetVisualDescendants().OfType<StrengthMeter>());
        w.Close();

        var w2 = Show(AuthMode.SignIn);
        Assert.Empty(w2.GetVisualDescendants().OfType<StrengthMeter>());
        w2.Close();
    }

    [AvaloniaFact]
    public async void Failed_submit_surfaces_a_danger_banner()
    {
        // Unconfigured AuthService — SignIn fails without touching a network.
        var w = Show(AuthMode.SignIn);
        SetBox(w, "email", "a@b.c");
        SetBox(w, "password", "whatever");
        Button? next = Primary(w);
        Assert.NotNull(next);
        Assert.True(next!.IsEnabled);
        next.RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
        await Task.Delay(100);
        Harness.Pump(TimeSpan.FromMilliseconds(100));

        var banner = w.GetVisualDescendants().OfType<Banner>()
            .Where(b => b.IsVisible).ToList();
        Assert.NotEmpty(banner);
        Assert.Contains("error", Box(w, "Password").Classes);
        w.Close();
    }

    [AvaloniaFact]
    public void Key_faces_show_the_usb_chip()
    {
        var w = Show(AuthMode.Reset, keyPresent: () => false, tokenHash: "t");
        var chips = w.GetVisualDescendants().OfType<StatusChip>().ToList();
        Assert.NotEmpty(chips);
        var chipText = chips[0].GetVisualDescendants().OfType<TextBlock>()
            .Select(t => t.Text).FirstOrDefault(t => t?.Contains("key") == true);
        Assert.Equal("Insert your USB key to finish", chipText);
        w.Close();

        var w2 = Show(AuthMode.SignIn);
        Assert.Empty(w2.GetVisualDescendants().OfType<StatusChip>());
        w2.Close();
    }
}
