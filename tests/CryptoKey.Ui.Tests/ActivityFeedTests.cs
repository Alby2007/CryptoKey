using Avalonia.Controls;
using Avalonia.Headless.XUnit;
using Avalonia.VisualTree;
using Xunit;

namespace CryptoKey.Ui.Tests;

/// <summary>
/// The Activity page's incremental prepend: a new log line must appear
/// without a rebuild, respect the live filter, and cap the rendered rows.
/// </summary>
public class ActivityFeedTests
{
    private static TextBlock CountText(Window w)
        => w.GetVisualDescendants().OfType<TextBlock>()
            .First(t => t.Text?.EndsWith("entries") == true);

    [AvaloniaFact]
    public void New_line_prepends_and_placeholder_clears()
    {
        (GuardService svc, GuardClient client, _) = Harness.Guard();
        using (svc)
        {
            var page = new ActivityPage(Harness.Context(client));
            var w = new Window { Content = page };
            w.Show();
            Harness.Pump(TimeSpan.FromMilliseconds(100));

            int baseline = client.Activity.Count;
            svc.Log("test-feed-marker");
            Harness.Pump(TimeSpan.FromMilliseconds(100));

            Assert.Equal($"1 of {baseline + 1} entries", CountText(w).Text);
            Assert.DoesNotContain(w.GetVisualDescendants().OfType<TextBlock>(),
                t => t.Text == "No matching activity.");
            w.Close();
        }
    }

    [AvaloniaFact]
    public void Rendered_rows_cap_at_300()
    {
        (GuardService svc, GuardClient client, _) = Harness.Guard();
        using (svc)
        {
            var page = new ActivityPage(Harness.Context(client));
            var w = new Window { Content = page };
            w.Show();
            Harness.Pump(TimeSpan.FromMilliseconds(50));

            int baseline = client.Activity.Count;
            for (int i = 0; i < 310; i++)
                svc.Log($"flood-{i}");
            Harness.Pump(TimeSpan.FromMilliseconds(200));

            Assert.Equal($"300 of {baseline + 310} entries", CountText(w).Text);
            w.Close();
        }
    }
}
