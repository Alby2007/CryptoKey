using Avalonia.Headless.XUnit;
using Avalonia.Threading;
using Xunit;

namespace CryptoKey.Ui.Tests;

/// <summary>The harness itself must run timers, or every timing test is vacuous.</summary>
public class HarnessTests
{
    [AvaloniaFact]
    public void Pump_runs_dispatcher_timers()
    {
        int ticks = 0;
        DispatcherTimer t = Kit.Timer(TimeSpan.FromMilliseconds(20), DispatcherPriority.Normal, () => ticks++);
        t.Start();
        Harness.Pump(TimeSpan.FromMilliseconds(400));
        t.Stop();
        Assert.True(ticks >= 5, $"only {ticks} ticks");
    }

    [AvaloniaFact]
    public void Kit_timers_start_stopped()
    {
        int ticks = 0;
        Kit.Timer(TimeSpan.FromMilliseconds(10), DispatcherPriority.Normal, () => ticks++);
        Harness.Pump(TimeSpan.FromMilliseconds(200));
        Assert.Equal(0, ticks);
    }
}
