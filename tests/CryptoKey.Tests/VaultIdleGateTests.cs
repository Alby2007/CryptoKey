using Xunit;
namespace CryptoKey.Tests;

/// <summary>
/// Pure decider for the vault idle seal — threshold edges and which vault
/// states the feed suppression applies to.
/// </summary>
public class VaultIdleGateTests
{
    [Fact]
    public void Off_when_minutes_zero()
    {
        Assert.False(VaultIdleGate.ShouldSeal(0, uint.MaxValue, VaultState.Mounted));
        Assert.False(VaultIdleGate.ShouldSuppressFeed(0, uint.MaxValue, VaultState.Sealed));
    }

    [Fact]
    public void Seal_fires_only_mounted_past_threshold()
    {
        uint justUnder = 1u * 60_000 - 1;
        uint at = 1u * 60_000;
        Assert.False(VaultIdleGate.ShouldSeal(1, justUnder, VaultState.Mounted));
        Assert.True(VaultIdleGate.ShouldSeal(1, at, VaultState.Mounted));
        Assert.False(VaultIdleGate.ShouldSeal(1, at, VaultState.Unsealed));
        Assert.False(VaultIdleGate.ShouldSeal(1, at, VaultState.Sealed));
        Assert.False(VaultIdleGate.ShouldSeal(1, at, VaultState.NoImage));
    }

    [Fact]
    public void Suppress_skips_closed_states_while_idle()
    {
        uint past = 10u * 60_000;
        // Sealed family — feeding would re-unseal every poll.
        Assert.True(VaultIdleGate.ShouldSuppressFeed(5, past, VaultState.Sealed));
        Assert.True(VaultIdleGate.ShouldSuppressFeed(5, past, VaultState.Corrupt));
        Assert.True(VaultIdleGate.ShouldSuppressFeed(5, past, VaultState.SealedDead));
        Assert.True(VaultIdleGate.ShouldSuppressFeed(5, past, VaultState.NeedsDriver));
        // Open states keep feeding — the vault is already unsealed anyway.
        Assert.False(VaultIdleGate.ShouldSuppressFeed(5, past, VaultState.Mounted));
        Assert.False(VaultIdleGate.ShouldSuppressFeed(5, past, VaultState.Unsealed));
    }

    [Fact]
    public void Suppress_lifts_below_threshold()
    {
        Assert.False(VaultIdleGate.ShouldSuppressFeed(5, 4u * 60_000, VaultState.Sealed));
    }
}
