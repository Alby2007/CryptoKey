using Xunit;
namespace CryptoKey.Tests;

public class RotateKeyfilesTests
{
    [Fact]
    public void Writes_only_letters_that_already_have_keyfiles()
    {
        string a = TestDisk.TempDir(), b = TestDisk.TempDir();
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig config = TestDisk.NewConfig(secret);
        TestDisk.WriteKeyfile(b, secret, config); // A has none

        byte[] envelope = KeyVerifier.WrapKeyfile(TestDisk.RandomSecret(), config);
        var results = KeyVerifier.RotateKeyfiles(TestDisk.For(a, b), envelope);

        Assert.Single(results);
        Assert.Equal(b, results[0].Letter);
        Assert.Null(results[0].Error);
        Assert.False(File.Exists(KeyVerifier.KeyFilePath(a)));
        Assert.True(File.ReadAllBytes(KeyVerifier.KeyFilePath(b)).SequenceEqual(envelope));
    }

    [Fact]
    public void No_keyfile_anywhere_re_arms_first_letter()
    {
        string a = TestDisk.TempDir(), b = TestDisk.TempDir();
        KeyConfig config = TestDisk.NewConfig(TestDisk.RandomSecret());
        byte[] envelope = KeyVerifier.WrapKeyfile(TestDisk.RandomSecret(), config);

        var results = KeyVerifier.RotateKeyfiles(TestDisk.For(a, b), envelope);

        Assert.Single(results);
        Assert.Equal(a, results[0].Letter); // first letter re-armed
        Assert.True(File.ReadAllBytes(KeyVerifier.KeyFilePath(a)).SequenceEqual(envelope));
        Assert.False(File.Exists(KeyVerifier.KeyFilePath(b)));
    }

    [Fact]
    public void Read_back_verification_returns_null_errors_on_success()
    {
        string a = TestDisk.TempDir();
        KeyConfig config = TestDisk.NewConfig(TestDisk.RandomSecret());
        TestDisk.WriteKeyfile(a, TestDisk.RandomSecret(), config);

        var results = KeyVerifier.RotateKeyfiles(TestDisk.For(a),
            KeyVerifier.WrapKeyfile(TestDisk.RandomSecret(), config));

        Assert.All(results, r => Assert.Null(r.Error));
    }

    [Fact]
    public void Unwritable_letter_reports_error_not_throw()
    {
        // A bogus letter whose parent doesn't exist makes the write fail.
        string bad = Path.Combine(Path.GetTempPath(), "cktest-missing-" + Guid.NewGuid().ToString("N"));
        KeyConfig config = TestDisk.NewConfig(TestDisk.RandomSecret());
        // Pre-seed a "keyfile exists" marker is impossible on a missing dir —
        // instead give the disk no keyfiles so it re-arms `bad`… which fails.
        var results = KeyVerifier.RotateKeyfiles(TestDisk.For(bad),
            KeyVerifier.WrapKeyfile(TestDisk.RandomSecret(), config));

        Assert.Single(results);
        Assert.NotNull(results[0].Error);
    }
}
