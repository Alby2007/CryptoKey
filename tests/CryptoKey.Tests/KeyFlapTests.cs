using Xunit;

namespace CryptoKey.Tests;

/// <summary>
/// Marginal-drive hysteresis: a suspended/flapping enclosure drops the
/// device node and re-enumerates inside a second, and transiently reports
/// the disk while its volume still stalls. Removal events re-confirm once
/// (a re-attach inside the window cancels the lock); a verify failure while
/// unlocked takes two consecutive strikes. Real pulls and sustained read
/// failures still lock — just a poll later, and confirmed.
/// </summary>
public class KeyFlapTests : IDisposable
{
    public KeyFlapTests()
    {
        AuthService.SetCurrent(null);
        TokenStore.Clear();
        AuthService.PendingStore.Clear();
        ThrottleStore.Clear();
        TestPlatform.TestUsbEnumerator.Disks.Clear();
    }

    public void Dispose()
    {
        AuthService.SetCurrent(null);
        TokenStore.Clear();
        AuthService.PendingStore.Clear();
        ThrottleStore.Clear();
        TestPlatform.TestUsbEnumerator.Disks.Clear();
    }

    /// <summary>
    /// Bound install, key enrolled + attached, guard started. The account
    /// binding is what arms <see cref="AuthService.ArmedForAutoLock"/> —
    /// an unbound install never auto-locks by design.
    /// </summary>
    private static GuardService StartedUnlocked(string dir, out TestPlatform.TestKeyMonitor mon)
    {
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig cfg = TestDisk.NewConfig(secret);
        cfg.Account = AccountRecord.Create("u1", "a@b.c", "acct-pw");
        cfg.Guard.Watchdog = false;
        cfg.Guard.UpdateCheckEnabled = false;
        TestDisk.WriteKeyfile(dir, secret, cfg);
        AuthService.SetCurrent(new AuthService(null, null));
        TestPlatform.TestUsbEnumerator.Disks.Add(TestDisk.For(dir));
        var svc = new GuardService(cfg, devMode: false, forceClassic: false);
        svc.RemovalConfirm = TimeSpan.FromMilliseconds(200);
        svc.Start(); // key present → verified at startup → Unlocked
        Assert.Equal(GuardState.Unlocked, svc.State);
        mon = TestPlatform.TestKeyMonitorFactory.Last!;
        return svc;
    }

    [Fact]
    public void Removal_flap_inside_the_confirm_window_never_locks()
    {
        string dir = TestDisk.TempDir();
        using var svc = StartedUnlocked(dir, out var mon);

        // The enclosure drops the node then re-enumerates inside the window —
        // the pending confirm must see it back and stand down entirely.
        TestPlatform.TestUsbEnumerator.Disks.Clear();
        mon.FireChanged(false);
        TestPlatform.TestUsbEnumerator.Disks.Add(TestDisk.For(dir));
        mon.FireChanged(true);

        Thread.Sleep(600); // well past the confirm window
        Assert.Equal(GuardState.Unlocked, svc.State);
    }

    [Fact]
    public void Real_removal_locks_once_the_confirm_window_passes()
    {
        string dir = TestDisk.TempDir();
        using var svc = StartedUnlocked(dir, out var mon);

        TestPlatform.TestUsbEnumerator.Disks.Clear();
        mon.FireChanged(false);
        Assert.Equal(GuardState.Unlocked, svc.State); // no instant lock

        Assert.True(SpinWait.SpinUntil(
            () => svc.State == GuardState.Locked, TimeSpan.FromSeconds(10)),
            "never locked on a real pull");
    }

    [Fact]
    public void Single_transient_read_error_does_not_lock()
    {
        string dir = TestDisk.TempDir();
        string deadDir = TestDisk.TempDir(); // same serial, no keyfile on it
        using var svc = StartedUnlocked(dir, out var mon);
        var dead = TestDisk.For(deadDir);

        mon.FireChecked(dead); // strike 1 — a stalled volume, not a pull
        Assert.Equal(GuardState.Unlocked, svc.State);
        mon.FireChecked(TestDisk.For(dir)); // healthy read resets the streak
        Assert.Equal(GuardState.Unlocked, svc.State);
        mon.FireChecked(dead); // strike 1 again
        Assert.Equal(GuardState.Unlocked, svc.State);
        mon.FireChecked(dead); // strike 2 — sustained failure locks
        Assert.Equal(GuardState.Locked, svc.State);
    }

    [Fact]
    public void Startup_absence_still_locks_immediately()
    {
        string dir = TestDisk.TempDir();
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig cfg = TestDisk.NewConfig(secret);
        cfg.Account = AccountRecord.Create("u1", "a@b.c", "acct-pw");
        cfg.Guard.Watchdog = false;
        cfg.Guard.UpdateCheckEnabled = false;
        TestDisk.WriteKeyfile(dir, secret, cfg);
        AuthService.SetCurrent(new AuthService(null, null));
        // Disk never enters Disks — absent at boot is fail-closed, no window.
        using var svc = new GuardService(cfg, devMode: false, forceClassic: false);
        svc.Start();
        Assert.Equal(GuardState.Locked, svc.State);
    }
}
