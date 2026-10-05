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

    [Fact]
    public void Warn_fires_once_at_the_lead_edge_then_locks()
    {
        var gate = new IdleLockGate(minutes: 1); // warn 40s, lock 60s

        Assert.Equal(IdleVerdict.None, gate.Check(39_999));
        Assert.Equal(IdleVerdict.Warn, gate.Check(40_000));
        Assert.Equal(IdleVerdict.None, gate.Check(50_000)); // same streak — no repeat
        Assert.Equal(IdleVerdict.Lock, gate.Check(60_000));
        Assert.Equal(IdleVerdict.None, gate.Check(70_000)); // suppressed
    }

    [Fact]
    public void Warn_re_arms_after_input_returns()
    {
        var gate = new IdleLockGate(minutes: 1);

        Assert.Equal(IdleVerdict.Warn, gate.Check(45_000));
        Assert.Equal(IdleVerdict.None, gate.Check(2_000));  // input seen — both edges reset
        Assert.Equal(IdleVerdict.Warn, gate.Check(41_000)); // next streak warns again
    }

    [Fact]
    public void ShouldLock_matches_the_lock_verdict()
    {
        var gate = new IdleLockGate(minutes: 1);

        Assert.False(gate.ShouldLock(45_000)); // warn band — not a lock
        Assert.True(gate.ShouldLock(60_000));
    }
}
