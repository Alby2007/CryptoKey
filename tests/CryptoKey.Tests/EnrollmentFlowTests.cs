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
}
