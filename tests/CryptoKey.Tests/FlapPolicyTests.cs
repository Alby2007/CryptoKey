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

    // ---- Foreign-window sentinel policy ----

    [Theory]
    [InlineData("ctfmon")]
    [InlineData("TextInputHost")]
    [InlineData("CTFMON")]            // case-insensitive
    [InlineData("textinputhost")]
    public void Input_furniture_is_a_benign_resident(string proc)
        => Assert.True(FlapPolicy.IsBenignDesktopResident(proc));

    [Theory]
    [InlineData("taskmgr")]           // the CAD→Task-Manager hole
    [InlineData("Taskmgr")]
    [InlineData("osk")]
    [InlineData("OSK")]
    [InlineData("Magnify")]
    [InlineData("Narrator")]
    [InlineData("explorer")]
    [InlineData("cmd")]
    public void Foreign_apps_are_not_benign_residents(string proc)
        => Assert.False(FlapPolicy.IsBenignDesktopResident(proc));

    // ---- Sentinel verdicts ----

    [Fact]
    public void Visible_foreign_window_is_an_intruder()
        => Assert.Equal(FlapPolicy.ForeignWindowVerdict.Intruder,
            FlapPolicy.ClassifyForeignWindow(visible: true, "taskmgr"));

    [Fact]
    public void Visible_name_unresolvable_window_is_still_an_intruder()
        // Protected/elevated processes resolve no name — visibility alone
        // is conclusive; nothing legit paints on a private desktop.
        => Assert.Equal(FlapPolicy.ForeignWindowVerdict.Intruder,
            FlapPolicy.ClassifyForeignWindow(visible: true, null));

    [Fact]
    public void Invisible_foreign_window_is_inconclusive()
        => Assert.Equal(FlapPolicy.ForeignWindowVerdict.Inconclusive,
            FlapPolicy.ClassifyForeignWindow(visible: false, "taskmgr"));

    [Fact]
    public void Invisible_unnamed_window_is_inconclusive()
        => Assert.Equal(FlapPolicy.ForeignWindowVerdict.Inconclusive,
            FlapPolicy.ClassifyForeignWindow(visible: false, null));

    [Fact]
    public void Furniture_is_benign_even_when_visible()
        => Assert.Equal(FlapPolicy.ForeignWindowVerdict.Benign,
            FlapPolicy.ClassifyForeignWindow(visible: true, "ctfmon"));

    [Fact]
    public void Furniture_is_benign_when_invisible()
        => Assert.Equal(FlapPolicy.ForeignWindowVerdict.Benign,
            FlapPolicy.ClassifyForeignWindow(visible: false, "TextInputHost"));

    // ---- Unreadable-input escalation ----

    [Fact]
    public void Unreadable_streak_does_not_fire_before_the_threshold()
    {
        var s = new UnreadableStreak();
        for (int i = 0; i < FlapPolicy.UnreadableTicksBeforeLock - 1; i++)
            Assert.False(s.RecordUnreadable());
    }

    [Fact]
    public void Unreadable_streak_fires_exactly_at_the_threshold()
    {
        var s = new UnreadableStreak();
        for (int i = 0; i < FlapPolicy.UnreadableTicksBeforeLock - 1; i++)
            s.RecordUnreadable();
        Assert.True(s.RecordUnreadable());           // tick 10 — the one shot
        Assert.False(s.RecordUnreadable());          // latched — no repeat
        Assert.False(s.RecordUnreadable());
    }

    [Fact]
    public void Readable_tick_resets_the_unreadable_streak()
    {
        var s = new UnreadableStreak();
        for (int i = 0; i < FlapPolicy.UnreadableTicksBeforeLock; i++)
            s.RecordUnreadable();                    // fired + latched
        s.Reset();                                   // desktop readable again
        for (int i = 0; i < FlapPolicy.UnreadableTicksBeforeLock - 1; i++)
            Assert.False(s.RecordUnreadable());
        Assert.True(s.RecordUnreadable());           // a new streak can fire again
    }

    // ---- Supervisor-death fail-closed gate ----

    [Fact]
    public void Locked_enabled_alive_to_dead_escalates()
        => Assert.True(FlapPolicy.ShouldEscalateSupervisorDeath(
            locked: true, enabled: true, wasAlive: true, alive: false));

    [Fact]
    public void Unlocked_supervisor_death_does_not_escalate()
        => Assert.False(FlapPolicy.ShouldEscalateSupervisorDeath(
            locked: false, enabled: true, wasAlive: true, alive: false));

    [Fact]
    public void Disabled_watchdog_death_does_not_escalate()
        => Assert.False(FlapPolicy.ShouldEscalateSupervisorDeath(
            locked: true, enabled: false, wasAlive: true, alive: false));

    [Fact]
    public void Never_alive_supervisor_does_not_escalate()
        => Assert.False(FlapPolicy.ShouldEscalateSupervisorDeath(
            locked: true, enabled: true, wasAlive: false, alive: false));

    [Fact]
    public void Still_alive_supervisor_does_not_escalate()
        => Assert.False(FlapPolicy.ShouldEscalateSupervisorDeath(
            locked: true, enabled: true, wasAlive: true, alive: true));
}
