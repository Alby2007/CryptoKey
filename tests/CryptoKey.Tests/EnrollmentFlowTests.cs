using Xunit;

namespace CryptoKey.Tests;

/// <summary>
/// The enrollment state machine both front ends drive — the CLI and the GUI
/// wizard can't drift from these rules because neither re-implements them.
/// </summary>
public class EnrollmentFlowTests
{
    private static UsbDisk Disk(string serial, params string[] volumes)
        => new("TEST\\DISK", serial, "Test Disk", volumes.ToList());

    [Fact]
    public void SelectDisk_without_a_volume_is_refused()
    {
        var flow = new EnrollmentFlow();
        Assert.NotNull(flow.SelectDisk(Disk("TEST-SERIAL")));
        Assert.Null(flow.Phrase);
    }

    [Fact]
    public void SelectDisk_generates_a_phrase_and_flags_blank_serials()
    {
        var flow = new EnrollmentFlow();
        Assert.Null(flow.SelectDisk(Disk("", TestDisk.TempDir())));
        Assert.NotNull(flow.DiskWarning);
        Assert.NotNull(flow.Phrase);

        Assert.Null(flow.SelectDisk(Disk("TEST-SERIAL", TestDisk.TempDir())));
        Assert.Null(flow.DiskWarning);
    }

    [Fact]
    public void Confirm_forgives_case_and_separators()
    {
        var flow = new EnrollmentFlow();
        flow.SelectDisk(Disk("TEST-SERIAL", TestDisk.TempDir()));
        string sloppy = flow.Phrase!.Replace("-", " ").ToLowerInvariant();
        Assert.Equal(ConfirmResult.Match, flow.Confirm(sloppy));
        Assert.True(flow.Confirmed);
    }

    [Fact]
    public void Three_mismatches_exhaust_and_commit_refuses()
    {
        var flow = new EnrollmentFlow();
        flow.SelectDisk(Disk("TEST-SERIAL", TestDisk.TempDir()));
        Assert.Equal(ConfirmResult.Mismatch, flow.Confirm("nope"));
        Assert.Equal(ConfirmResult.Mismatch, flow.Confirm("still nope"));
        Assert.Equal(ConfirmResult.Exhausted, flow.Confirm("nope again"));
        // Even the right phrase is refused once exhausted.
        Assert.Equal(ConfirmResult.Exhausted, flow.Confirm(flow.Phrase!));
        Assert.False(flow.Commit().Ok);
    }

    [Fact]
    public void Commit_before_confirm_is_refused()
    {
        var flow = new EnrollmentFlow();
        flow.SelectDisk(Disk("TEST-SERIAL", TestDisk.TempDir()));
        Assert.False(flow.Commit().Ok);
    }

    [Fact]
    public void Commit_writes_a_keyfile_that_verifies_with_configured_policy()
    {
        string dir = TestDisk.TempDir();
        UsbDisk disk = Disk("TEST-SERIAL", dir);
        var flow = new EnrollmentFlow();
        flow.SelectDisk(disk);
        string phrase = flow.Phrase!;
        flow.Confirm(phrase);

        EnrollResult r = flow.Commit(g => g.UnlockPolicy = UnlockPolicy.KeyAndPassphrase);

        Assert.True(r.Ok, r.Message);
        Assert.NotNull(r.Config);
        Assert.Equal(UnlockPolicy.KeyAndPassphrase, r.Config!.Guard.UnlockPolicy);
        Assert.True(File.Exists(r.KeyPath));
        Assert.True(KeyVerifier.Verify(r.Config, disk, out string why), why);
        Assert.True(ConfigStore.VerifyPassphrase(r.Config, phrase));
        Assert.Null(flow.Phrase); // dropped after commit
        KeyConfig? saved = ConfigStore.Load();
        Assert.Equal(r.Config.SecretHash, saved?.SecretHash);
    }

    [Fact]
    public void Commit_with_an_unwritable_volume_fails_cleanly()
    {
        string missing = Path.Combine(TestDisk.TempDir(), "gone", "deeper");
        var flow = new EnrollmentFlow();
        flow.SelectDisk(Disk("TEST-SERIAL", missing));
        flow.Confirm(flow.Phrase!);
        string? before = File.Exists(ConfigStore.ConfigPath)
            ? File.ReadAllText(ConfigStore.ConfigPath) : null;

        EnrollResult r = flow.Commit();

        Assert.False(r.Ok);
        string? after = File.Exists(ConfigStore.ConfigPath)
            ? File.ReadAllText(ConfigStore.ConfigPath) : null;
        Assert.Equal(before, after);
    }

    // Re-enroll while a vault image exists: the image's key slots unwrap
    // only under the CURRENT secret — a sealed vault can't re-wrap onto the
    // new key and would die silently. Commit gates on a live vault-open
    // report (or refuses outright when no guard answers).

    /// <summary>Enrolled Existing + a file at its vault image path. The
    /// caller disposes <paramref name="imagePath"/> when done — a leftover
    /// path pointing at a deleted file can't gate the next test.</summary>
    private static EnrollmentFlow ArmedFlow(out string imagePath)
    {
        KeyConfig existing = TestDisk.NewConfig(TestDisk.RandomSecret());
        imagePath = Path.Combine(TestDisk.TempDir(), "vault.ckv");
        File.WriteAllBytes(imagePath, new byte[16]); // contents never read
        existing.Guard.VaultImagePath = imagePath;
        ConfigStore.Save(existing);
        var flow = new EnrollmentFlow();
        Assert.NotNull(flow.Existing);
        flow.SelectDisk(Disk("NEW-SERIAL", TestDisk.TempDir()));
        flow.Confirm(flow.Phrase!);
        return flow;
    }

    [Fact]
    public void Commit_refuses_reenroll_while_the_vault_is_sealed()
    {
        var flow = ArmedFlow(out string imagePath);
        try
        {
            string oldSerial = flow.Existing!.DeviceSerial;
            flow.VaultStatusProbe = () => "ok vault state=sealed exists=yes";

            EnrollResult r = flow.Commit();

            Assert.False(r.Ok);
            Assert.Contains("vault", r.Message);
            Assert.Equal(oldSerial, ConfigStore.Load()!.DeviceSerial); // untouched
        }
        finally { File.Delete(imagePath); }
    }

    [Theory]
    [InlineData("sealed")]
    [InlineData("sealeddead")]
    [InlineData("corrupt")]
    [InlineData("tpmlocked")]
    [InlineData("rolledback")]
    [InlineData("disabled")]
    public void Closed_vault_states_all_refuse_reenroll(string state)
    {
        var flow = ArmedFlow(out string imagePath);
        try
        {
            flow.VaultStatusProbe = () => $"ok vault state={state} exists=yes";
            Assert.False(flow.Commit().Ok);
        }
        finally { File.Delete(imagePath); }
    }

    [Theory]
    [InlineData("unsealed")]
    [InlineData("mounted")]
    [InlineData("needsdriver")] // volume key held — driver presence doesn't matter
    public void Open_vault_states_allow_reenroll(string state)
    {
        var flow = ArmedFlow(out string imagePath);
        try
        {
            int oldCount = flow.Existing!.RotationCount;
            flow.VaultStatusProbe = () => $"ok vault state={state} exists=yes";
            EnrollResult r = flow.Commit();
            Assert.True(r.Ok, r.Message);
            // A fresh secret is a new generation — the counter rides forward
            // so the open vault's slot re-wrap (gen-change triggered) fires.
            Assert.Equal(oldCount + 1, r.Config!.RotationCount);
        }
        finally { File.Delete(imagePath); }
    }

    [Fact]
    public void Commit_refuses_reenroll_when_no_guard_answers()
    {
        var flow = ArmedFlow(out string imagePath);
        try
        {
            flow.VaultStatusProbe = () => null;
            EnrollResult r = flow.Commit();
            Assert.False(r.Ok);
            Assert.Contains("vault", r.Message);
        }
        finally { File.Delete(imagePath); }
    }

    [Fact]
    public void Vault_gate_skips_first_enrollment()
    {
        // No Existing config — there is no prior enrollment an image could
        // be bound to, so a stray file at the image path can't veto setup.
        // The load chain is primary → .bak → third copy — all three go.
        foreach (string p in new[] { ConfigStore.ConfigPath,
                 ConfigStore.BackupPath, TestInit.ThirdCopyPath })
            if (File.Exists(p))
                File.Delete(p);
        var flow = new EnrollmentFlow();
        Assert.Null(flow.Existing);
        flow.SelectDisk(Disk("TEST-SERIAL", TestDisk.TempDir()));
        flow.Confirm(flow.Phrase!);
        flow.VaultStatusProbe = () => "ok vault state=sealed";
        Assert.True(flow.Commit().Ok);
    }
}
