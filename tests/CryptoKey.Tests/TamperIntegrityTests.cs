using Xunit;

namespace CryptoKey.Tests;

/// <summary>
/// M3 — a canon mismatch is held, never healed silently: the phrase path
/// closes until a key-present `accept-config`. M4 — the V2Only latch:
/// raw pre-attestation keyfiles stop counting once envelopes exist, and
/// a legacy-file match counts dirty while an account is bound.
/// </summary>
public class TamperIntegrityTests : IDisposable
{
    public TamperIntegrityTests()
    {
        AuthService.SetCurrent(null);
        TokenStore.Clear();
        AuthService.PendingStore.Clear();
        TestPlatform.TestUsbEnumerator.Disks.Clear();
    }

    public void Dispose()
    {
        AuthService.SetCurrent(null);
        TokenStore.Clear();
        AuthService.PendingStore.Clear();
        TestPlatform.TestUsbEnumerator.Disks.Clear();
    }

    private static KeyConfig FreshCfg(string dir, byte[] secret)
    {
        KeyConfig cfg = TestDisk.NewConfig(secret);
        cfg.Guard.Watchdog = false;
        cfg.Guard.UpdateCheckEnabled = false;
        TestDisk.WriteKeyfile(dir, secret, cfg);
        AuthService.SetCurrent(new AuthService(null, null));
        return cfg;
    }

    [Fact]
    public void Canon_mismatch_latches_and_needs_explicit_accept()
    {
        string dir = TestDisk.TempDir();
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig cfg = FreshCfg(dir, secret);
        using var svc = new GuardService(cfg, devMode: false, forceClassic: false);
        svc.Start();
        var mon = TestPlatform.TestKeyMonitorFactory.Last!;
        var disk = TestDisk.For(dir);

        // Clean poll first — the envelope attests the original canon.
        mon.FireChecked(disk);
        Assert.Contains("integrity=clean", svc.DispatchCommand("status"));

        // Off-app canon edit (idle-lock minutes) — the stored envelope no
        // longer matches the live config.
        cfg.Guard.IdleLockMinutes += 7;
        mon.FireChecked(disk);
        Assert.Contains("integrity=dirty", svc.DispatchCommand("status"));

        // Holding the key alone doesn't heal it — accept is explicit. The
        // re-attest rewrite lands on a later poll (the write is async), so
        // spin until the envelope verifies clean again.
        Assert.StartsWith("ok accepted", svc.DispatchCommand("accept-config"));
        Assert.True(SpinWait.SpinUntil(() =>
        {
            mon.FireChecked(disk);
            return svc.DispatchCommand("status").Contains("integrity=clean");
        }, TimeSpan.FromSeconds(15)), "re-attested envelope never verified clean");
    }

    [Fact]
    public void Dirty_canon_holds_the_phrase_path_closed()
    {
        string dir = TestDisk.TempDir();
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig cfg = FreshCfg(dir, secret);
        using var svc = new GuardService(cfg, devMode: false, forceClassic: false);
        svc.Start();
        var mon = TestPlatform.TestKeyMonitorFactory.Last!;
        mon.FireChecked(TestDisk.For(dir));
        cfg.Guard.IdleLockMinutes += 7;
        mon.FireChecked(TestDisk.For(dir));

        Assert.StartsWith("ok", svc.DispatchCommand("lock"));
        var surface = TestPlatform.TestLockSurfaceFactory.Last!;
        // The CORRECT phrase — held closed while integrity is dirty.
        surface.Submit("passphrase-ok");
        Assert.True(SpinWait.SpinUntil(
            () => surface.LastStatus?.Contains("integrity") == true,
            TimeSpan.FromSeconds(10)), surface.LastStatus ?? "no status");
        Assert.Equal(GuardState.Locked, svc.State);
    }

    [Fact]
    public void Accept_config_refuses_without_a_verified_key()
    {
        string dir = TestDisk.TempDir();
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig cfg = FreshCfg(dir, secret);
        using var svc = new GuardService(cfg, devMode: false, forceClassic: false);
        svc.Start();
        // No poll, no key — nothing verified, nothing pending.
        Assert.StartsWith("ok nothing pending",
            svc.DispatchCommand("accept-config"));
    }

    [Fact]
    public void V2_only_refuses_raw_legacy_keyfiles()
    {
        string dir = TestDisk.TempDir();
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig cfg = FreshCfg(dir, secret);
        Assert.True(cfg.V2Only); // CreateNew latched it

        // A raw 64-byte file carrying the REAL secret — refused anyway.
        File.WriteAllBytes(KeyVerifier.KeyFilePath(dir), secret);
        KeyfileCheck check = KeyVerifier.Check(cfg, TestDisk.For(dir));
        Assert.Equal(SecretMatch.None, check.Match);
    }

    [Fact]
    public void First_v2_envelope_sighting_latches_v2_only()
    {
        // Upgraded-install path: config predates the flag (V2Only=false),
        // the drive carries a v2 envelope → the latch flips and persists.
        string dir = TestDisk.TempDir();
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig cfg = FreshCfg(dir, secret);
        cfg.V2Only = false;
        // Re-write the keyfile for the OLD canon (the flag is covered).
        TestDisk.WriteKeyfile(dir, secret, cfg);
        ConfigStore.Save(cfg);
        using var svc = new GuardService(cfg, devMode: false, forceClassic: false);
        svc.Start();
        var mon = TestPlatform.TestKeyMonitorFactory.Last!;
        mon.FireChecked(TestDisk.For(dir));

        Assert.True(cfg.V2Only);
        Assert.True(ConfigStore.Load()!.V2Only); // persisted latch
    }
}
