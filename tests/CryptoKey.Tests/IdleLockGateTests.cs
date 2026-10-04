using Xunit;

namespace CryptoKey.Tests;

public class IdleLockGateTests
{
    [Fact]
    public void Fires_once_then_suppresses_the_same_streak()
    {
        var gate = new IdleLockGate(minutes: 1); // 60_000ms threshold

        Assert.True(gate.ShouldLock(70_000));   // streak crosses → fire
        Assert.False(gate.ShouldLock(75_000));  // same streak → suppressed
        Assert.False(gate.ShouldLock(300_000)); // still suppressed
    }

    [Fact]
    public void Re_arms_after_input_returns()
    {
        var gate = new IdleLockGate(minutes: 1);

        Assert.True(gate.ShouldLock(70_000));
        Assert.False(gate.ShouldLock(5_000));   // input seen — below threshold, clears
        Assert.True(gate.ShouldLock(65_000));   // next streak fires again
    }

    [Fact]
    public void Below_threshold_never_fires()
    {
        var gate = new IdleLockGate(minutes: 5);

        Assert.False(gate.ShouldLock(0));
        Assert.False(gate.ShouldLock(299_999));
    }
}
