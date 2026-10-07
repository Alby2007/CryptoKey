using System.Text;
using Xunit;

namespace CryptoKey.Tests;

/// <summary>
/// `unenroll` — the phrase-verified, account-gated removal of the key
/// binding. The install (account, phrase, settings, vault epoch) survives;
/// only the key material clears, and the guard goes dormant — never
/// first-run, never auto-locks.
/// </summary>
public class UnenrollTests : IDisposable
{
    public UnenrollTests()
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

    /// <summary>An enrolled config with no account gate and no side jobs.</summary>
    private static KeyConfig FreshCfg()
    {
        KeyConfig cfg = TestDisk.NewConfig(TestDisk.RandomSecret());
        cfg.Guard.Watchdog = false;
        cfg.Guard.UpdateCheckEnabled = false;
        AuthService.SetCurrent(new AuthService(null, null));
        return cfg;
    }

    private static string B64(string text)
        => Convert.ToBase64String(Encoding.UTF8.GetBytes(text));

    [Fact]
    public void Unenroll_clears_key_material_and_keeps_the_install()
    {
        KeyConfig cfg = FreshCfg();
        cfg.Guard.IdleLockMinutes = 9;
        cfg.Guard.StrictTamper = true;
        cfg.VaultEpoch = 7;
        cfg.Account = AccountRecord.Create("u1", "a@b.c", "pw-123456");
        (string phraseSalt, string phraseHash, int iters) =
            (cfg.PassphraseSalt, cfg.PassphraseHash, cfg.PassphraseIterations);
        ConfigStore.Save(cfg);
        using var svc = new GuardService(cfg, devMode: false, forceClassic: false);

        string reply = svc.Unenroll("passphrase-ok");

        Assert.StartsWith("ok", reply);
        Assert.False(cfg.Enrolled);
        Assert.Equal("", cfg.DeviceSerial);
        Assert.Equal("", cfg.SecretSalt);
        Assert.Equal("", cfg.SecretHash);
        Assert.Equal("", cfg.PrevSecretHash);
        Assert.Equal(0, cfg.RotationCount);
        Assert.Null(cfg.LastRotationUtc);
        // Everything that isn't key material survives.
        Assert.Equal(phraseSalt, cfg.PassphraseSalt);
        Assert.Equal(phraseHash, cfg.PassphraseHash);
        Assert.Equal(iters, cfg.PassphraseIterations);
        Assert.Equal(7ul, cfg.VaultEpoch);
        Assert.Equal("a@b.c", cfg.Account?.Email);
        Assert.Equal(9, cfg.Guard.IdleLockMinutes);
        Assert.True(cfg.Guard.StrictTamper);

        // Persisted — a present-but-unenrolled config is dormant, not first-run.
        KeyConfig? loaded = ConfigStore.Load();
        Assert.NotNull(loaded);
        Assert.False(loaded!.Enrolled);
        Assert.Equal("a@b.c", loaded.Account?.Email);
        // The kept phrase still verifies — manual lock + vault recovery need it.
        Assert.True(ConfigStore.VerifyPassphrase(loaded, "passphrase-ok"));

        Assert.False(svc.Snapshot().Enrolled);
        Assert.Contains("enrolled=no", svc.DispatchCommand("status"));
    }

    [Fact]
    public void Wrong_phrase_is_refused_and_the_binding_survives()
    {
        KeyConfig cfg = FreshCfg();
        using var svc = new GuardService(cfg, devMode: false, forceClassic: false);

        Assert.StartsWith("err", svc.Unenroll("not-the-phrase"));
        Assert.True(cfg.Enrolled);
        Assert.Equal("TEST-SERIAL", cfg.DeviceSerial);
    }

    [Fact]
    public void Locked_unenroll_is_refused_before_the_phrase_or_auth()
    {
        // Removing the key from a locked box is just an unlock bypass —
        // refused before the phrase is even consulted, so the verb can't
        // be probed with a wrong phrase either.
        KeyConfig cfg = FreshCfg();
        using var svc = new GuardService(cfg, devMode: false, forceClassic: false);
        svc.Start();
        Assert.StartsWith("ok", svc.DispatchCommand("lock"));
        Assert.Equal(GuardState.Locked, svc.State);

        Assert.StartsWith("err locked", svc.Unenroll("passphrase-ok"));
        Assert.StartsWith("err locked",
            svc.DispatchCommand("unenroll " + B64("passphrase-ok")));
        Assert.True(cfg.Enrolled);
    }

    [Fact]
    public void A_vault_image_blocks_unenroll()
    {
        // The vault's contents are keyed to this enrollment — removing the
        // key strands them forever. The image must go first.
        string image = Path.Combine(TestDisk.TempDir(), "vault.ckv");
        File.WriteAllText(image, "fake image");
        KeyConfig cfg = FreshCfg();
        cfg.Guard.VaultEnabled = true;
        cfg.Guard.VaultImagePath = image;
        using var svc = new GuardService(cfg, devMode: false, forceClassic: false);

        string reply = svc.Unenroll("passphrase-ok");
        Assert.StartsWith("err", reply);
        Assert.Contains("vault", reply);
        Assert.True(cfg.Enrolled);
    }

    [Fact]
    public void Unenrolled_box_never_auto_locks()
    {
        // Dormant startup: no key bound → the startup check is a no-op.
        // Removal, resume, idle, and pause-expiry all funnel through the
        // same MaybeAutoLock gate — the !Enrolled return covers them.
        KeyConfig cfg = FreshCfg();
        cfg.DeviceSerial = "";
        cfg.SecretSalt = "";
        cfg.SecretHash = "";
        cfg.PrevSecretHash = "";
        cfg.RotationCount = 0;
        cfg.LastRotationUtc = null;
        Assert.False(cfg.Enrolled);
        using var svc = new GuardService(cfg, devMode: false, forceClassic: false);
        svc.Start(); // key "absent" — would lock if the funnel didn't gate

        Assert.Equal(GuardState.Unlocked, svc.State);
        // Manual lock still works — the safe direction never gates, and
        // the kept phrase is what unlocks it.
        Assert.StartsWith("ok", svc.DispatchCommand("lock"));
        Assert.Equal(GuardState.Locked, svc.State);
    }

    [Fact]
    public void Ipc_unenroll_is_auth_gated_then_phrase_gated()
    {
        KeyConfig cfg = FreshCfg();
        cfg.Account = AccountRecord.Create("u1", "a@b.c", "acct-pw");
        AuthService.SetCurrent(new AuthService(new SupabaseConfig
        {
            ProjectUrl = "https://test.supabase.co",
            AnonKey = "test-anon-key-0123456789abcdef",
        }, null));
        using var svc = new GuardService(cfg, devMode: false, forceClassic: false);

        string trailer = " |auth " + B64("acct-pw");
        // Gate order: account session first, the phrase arg second — a
        // caller shouldn't be prompted for the phrase while still unsigned.
        Assert.StartsWith("err AUTH_REQUIRED", svc.DispatchCommand("unenroll"));
        Assert.StartsWith("err PHRASE_REQUIRED",
            svc.DispatchCommand("unenroll" + trailer));
        Assert.StartsWith("err incorrect recovery phrase",
            svc.DispatchCommand("unenroll " + B64("wrong") + trailer));
        Assert.True(cfg.Enrolled);

        // Phrase + |auth trailer parse together — the b64 alphabet can't
        // collide with the '|' trailer separator.
        Assert.StartsWith("ok",
            svc.DispatchCommand("unenroll " + B64("passphrase-ok") + trailer));
        Assert.False(cfg.Enrolled);
    }

    [Fact]
    public void Keyfile_is_deleted_from_an_attached_drive()
    {
        string dir = TestDisk.TempDir();
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig cfg = FreshCfg();
        TestDisk.WriteKeyfile(dir, secret, cfg);
        string keyfile = KeyVerifier.KeyFilePath(dir);
        Assert.True(File.Exists(keyfile));
        // _lastDisk is null (the monitor stub never reports) — Unenroll
        // falls back to a fresh FindDisk over the attached list.
        TestPlatform.TestUsbEnumerator.Disks.Add(TestDisk.For(dir));
        using var svc = new GuardService(cfg, devMode: false, forceClassic: false);

        Assert.StartsWith("ok", svc.Unenroll("passphrase-ok"));
        Assert.False(File.Exists(keyfile));
    }

    [Fact]
    public void Unenroll_on_a_dormant_config_refuses_honestly()
    {
        // Second run of the verb is not a silent "ok" — there was nothing
        // to remove and the reply says so.
        KeyConfig cfg = FreshCfg();
        cfg.DeviceSerial = "";
        cfg.SecretSalt = "";
        cfg.SecretHash = "";
        using var svc = new GuardService(cfg, devMode: false, forceClassic: false);

        Assert.StartsWith("err no key enrolled", svc.Unenroll("passphrase-ok"));
        Assert.False(cfg.Enrolled);
    }

    [Fact]
    public void Null_key_fields_deserialize_as_unenrolled_not_a_crash()
    {
        // A crafted/hand-edited config can put JSON null in the string
        // fields — Enrolled must read false, never throw, everywhere it's
        // consulted (Start, Snapshot, status, every auto-lock funnel).
        File.WriteAllText(ConfigStore.ConfigPath,
            """{"DeviceSerial": null, "SecretSalt": null, "SecretHash": null}""");
        try
        {
            KeyConfig? loaded = ConfigStore.Load();
            Assert.NotNull(loaded);
            Assert.False(loaded!.Enrolled);
        }
        finally
        {
            File.Delete(ConfigStore.ConfigPath);
            File.Delete(ConfigStore.BackupPath);
        }
    }

    [Fact]
    public void Empty_serial_never_matches_a_blank_serial_disk()
    {
        // The dormant sentinel is "" — a drive that reports a blank serial
        // satisfies `SerialNumber == ""` if FindDisk doesn't refuse first.
        string dir = TestDisk.TempDir();
        TestPlatform.TestUsbEnumerator.Disks.Add(
            new UsbDisk("TEST\\DISK", "", "Blank-serial drive", [dir]));

        Assert.Null(Platform.Services.Usb.FindDisk(""));
    }

    [Fact]
    public void Reenroll_from_unenrolled_keeps_settings_account_and_epoch()
    {
        // `unenroll` leaves a present-but-dormant config; enrolling a fresh
        // key from it must not fall back to first-run semantics — account,
        // guard prefs, and the vault rollback fence all carry over.
        KeyConfig cfg = FreshCfg();
        cfg.Guard.IdleLockMinutes = 9;
        cfg.VaultEpoch = 11;
        cfg.Account = AccountRecord.Create("u1", "a@b.c", "pw-123456");
        ConfigStore.Save(cfg);
        using (var svc = new GuardService(cfg, devMode: false, forceClassic: false))
            Assert.StartsWith("ok", svc.Unenroll("passphrase-ok"));

        string dir = TestDisk.TempDir();
        var flow = new EnrollmentFlow();
        Assert.NotNull(flow.Existing);
        Assert.False(flow.Existing!.Enrolled); // dormant — not absent
        Assert.Null(flow.SelectDisk(TestDisk.For(dir)));
        Assert.Equal(ConfirmResult.Match, flow.Confirm(flow.Phrase!.AsSpan()));
        EnrollResult r = flow.Commit();

        Assert.True(r.Ok, r.Message);
        Assert.NotNull(r.Config);
        Assert.True(r.Config!.Enrolled);
        Assert.Equal(9, r.Config.Guard.IdleLockMinutes);
        Assert.Equal(11ul, r.Config.VaultEpoch);
        Assert.Equal("a@b.c", r.Config.Account?.Email);
        // A fresh binding — generation 1, new phrase hash.
        Assert.Equal(1, r.Config.RotationCount);
        Assert.True(File.Exists(KeyVerifier.KeyFilePath(dir)));
    }
}
