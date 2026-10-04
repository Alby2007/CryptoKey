using Xunit;

namespace CryptoKey.Tests;

public class FlapPolicyTests
{
    [Fact]
    public void Own_lock_desktop_is_healthy()
        => Assert.False(FlapPolicy.IsHostile("CryptoKeyLock", openFailed: false));

    [Fact]
    public void Winlogon_is_legit_sas_not_a_flap()
        => Assert.False(FlapPolicy.IsHostile("Winlogon", openFailed: false));

    [Fact]
    public void Failed_open_is_the_sas_acl_tell_not_a_flap()
        => Assert.False(FlapPolicy.IsHostile(null, openFailed: true));

    [Fact]
    public void Default_desktop_is_hostile()
        => Assert.True(FlapPolicy.IsHostile("Default", openFailed: false));

    [Fact]
    public void Attacker_created_desktop_is_hostile()
        => Assert.True(FlapPolicy.IsHostile("pwned", openFailed: false));

    [Fact]
    public void Unnameable_open_desktop_is_hostile()
        => Assert.True(FlapPolicy.IsHostile(null, openFailed: false));

    [Fact]
    public void Two_flaps_is_not_a_storm()
    {
        var c = new FlapCounter();
        var t = DateTime.UtcNow;
        Assert.False(c.Record(t));
        Assert.False(c.Record(t.AddSeconds(2)));
    }

    [Fact]
    public void Third_flap_in_window_is_a_storm()
    {
        var c = new FlapCounter();
        var t = DateTime.UtcNow;
        Assert.False(c.Record(t));
        Assert.False(c.Record(t.AddSeconds(3)));
        Assert.True(c.Record(t.AddSeconds(6)));
    }

    [Fact]
    public void Storm_stays_armed_while_flaps_keep_landing()
    {
        var c = new FlapCounter();
        var t = DateTime.UtcNow;
        c.Record(t); c.Record(t.AddSeconds(3)); c.Record(t.AddSeconds(6));
        // Each continued flap inside the window still reports storm —
        // the caller's LockWorkStation is idempotent so that's intended.
        Assert.True(c.Record(t.AddSeconds(8)));
    }

    [Fact]
    public void Old_flaps_age_out_and_the_attack_reaccumulates()
    {
        var c = new FlapCounter();
        var t = DateTime.UtcNow;
        c.Record(t); c.Record(t.AddSeconds(1));
        // 11s later both have aged out — this flap is a fresh count of 1.
        Assert.False(c.Record(t.AddSeconds(11)));
        Assert.False(c.Record(t.AddSeconds(12)));
        Assert.True(c.Record(t.AddSeconds(13)));
    }

    [Fact]
    public void Reset_clears_the_window()
    {
        var c = new FlapCounter();
        var t = DateTime.UtcNow;
        c.Record(t); c.Record(t.AddSeconds(1));
        c.Reset();
        Assert.False(c.Record(t.AddSeconds(2)));
    }
}
