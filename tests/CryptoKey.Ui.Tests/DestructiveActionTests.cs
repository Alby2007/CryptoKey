using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Headless.XUnit;
using Avalonia.Input;
using Avalonia.LogicalTree;
using Xunit;

namespace CryptoKey.Ui.Tests;

/// <summary>
/// Regression for a real incident: HoldButton's timer was built with the
/// auto-starting DispatcherTimer constructor, so every hold-to-confirm
/// button "confirmed" the moment the Vault page loaded — reformatting and
/// deleting the vault image with no user input. Nothing destructive may
/// ever complete without a genuine, full-length hold.
/// </summary>
public class DestructiveActionTests
{
    private static (Window Window, HoldButton Button) Show(HoldButton b)
    {
        var w = new Window { Width = 400, Height = 200, Content = b };
        b.HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Center;
        b.VerticalAlignment = Avalonia.Layout.VerticalAlignment.Center;
        w.Show();
        Harness.Pump(TimeSpan.FromMilliseconds(50));
        return (w, b);
    }

    private static Point Center(Window w, Control c)
        => c.TranslatePoint(new Point(c.Bounds.Width / 2, c.Bounds.Height / 2), w)!.Value;

    [AvaloniaFact]
    public void A_hold_button_never_confirms_on_its_own()
    {
        int fired = 0;
        var b = new HoldButton("Delete image", IconData.Trash) { HoldTime = TimeSpan.FromMilliseconds(300) };
        b.Confirmed += () => fired++;
        (Window w, _) = Show(b);
        Harness.Pump(TimeSpan.FromSeconds(1.2));
        Assert.Equal(0, fired);
        w.Close();
    }

    [AvaloniaFact]
    public void A_full_hold_confirms_exactly_once()
    {
        int fired = 0;
        var b = new HoldButton("Reformat", IconData.Refresh) { HoldTime = TimeSpan.FromMilliseconds(300) };
        b.Confirmed += () => fired++;
        (Window w, _) = Show(b);
        Point p = Center(w, b);
        w.MouseDown(p, MouseButton.Left);
        Harness.Pump(TimeSpan.FromMilliseconds(700));
        w.MouseUp(p, MouseButton.Left);
        Harness.Pump(TimeSpan.FromMilliseconds(400));
        Assert.Equal(1, fired);
        w.Close();
    }

    [AvaloniaFact]
    public void Releasing_early_cancels()
    {
        int fired = 0;
        var b = new HoldButton("Reformat", IconData.Refresh) { HoldTime = TimeSpan.FromMilliseconds(600) };
        b.Confirmed += () => fired++;
        (Window w, _) = Show(b);
        Point p = Center(w, b);
        w.MouseDown(p, MouseButton.Left);
        Harness.Pump(TimeSpan.FromMilliseconds(200));
        w.MouseUp(p, MouseButton.Left);
        Harness.Pump(TimeSpan.FromMilliseconds(900));
        Assert.Equal(0, fired);
        w.Close();
    }

    [AvaloniaFact]
    public void A_disabled_hold_button_cannot_confirm()
    {
        int fired = 0;
        var b = new HoldButton("Delete", IconData.Trash) { HoldTime = TimeSpan.FromMilliseconds(200), IsEnabled = false };
        b.Confirmed += () => fired++;
        (Window w, _) = Show(b);
        Point p = Center(w, b);
        w.MouseDown(p, MouseButton.Left);
        Harness.Pump(TimeSpan.FromMilliseconds(600));
        w.MouseUp(p, MouseButton.Left);
        Assert.Equal(0, fired);
        w.Close();
    }

    [AvaloniaFact]
    public void Loading_the_vault_page_confirms_nothing()
    {
        (GuardService svc, GuardClient client, _) = Harness.Guard();
        using (svc)
        {
            var page = new VaultPage(Harness.Context(client));
            var holds = page.GetLogicalDescendants().OfType<HoldButton>().ToList();
            Assert.NotEmpty(holds);
            int fired = 0;
            foreach (HoldButton h in holds)
                h.Confirmed += () => fired++;

            var w = new Window { Width = 1000, Height = 800, Content = page };
            w.Show();
            Harness.Pump(TimeSpan.FromSeconds(2));

            Assert.Equal(0, fired);
            Assert.DoesNotContain(client.Activity, l =>
                l.Contains("reformatted", StringComparison.OrdinalIgnoreCase)
                || l.Contains("image deleted", StringComparison.OrdinalIgnoreCase));
            w.Close();
        }
    }
}
