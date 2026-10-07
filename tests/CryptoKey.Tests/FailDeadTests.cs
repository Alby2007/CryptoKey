using Xunit;

namespace CryptoKey.Tests;

/// <summary>
/// M7 — fail-dead paths OS-lock a locked session instead of freeing input
/// onto an unattended open desktop.
/// </summary>
public class FailDeadTests
{
    [Fact]
    public void ReleaseInput_while_locked_os_locks_the_session()
    {
        KeyConfig cfg = TestDisk.NewConfig(TestDisk.RandomSecret());
        cfg.Guard.Watchdog = false;
        cfg.Guard.UpdateCheckEnabled = false;
        AuthService.SetCurrent(new AuthService(null, null));
        TestPlatform.TestSystemActions.LockScreenCalls = 0;
        try
        {
            using var svc = new GuardService(cfg, devMode: false, forceClassic: false);
            svc.Start();
            Assert.StartsWith("ok", svc.DispatchCommand("lock"));
            svc.ReleaseInput();
            Assert.Equal(1, TestPlatform.TestSystemActions.LockScreenCalls);
        }
        finally
        {
            AuthService.SetCurrent(null);
        }
    }

    [Fact]
    public void ReleaseInput_while_unlocked_does_not_os_lock()
    {
        KeyConfig cfg = TestDisk.NewConfig(TestDisk.RandomSecret());
        cfg.Guard.Watchdog = false;
        cfg.Guard.UpdateCheckEnabled = false;
        AuthService.SetCurrent(new AuthService(null, null));
        TestPlatform.TestSystemActions.LockScreenCalls = 0;
        try
        {
            using var svc = new GuardService(cfg, devMode: false, forceClassic: false);
            svc.Start();
            svc.ReleaseInput();
            Assert.Equal(0, TestPlatform.TestSystemActions.LockScreenCalls);
        }
        finally
        {
            AuthService.SetCurrent(null);
        }
    }
}
