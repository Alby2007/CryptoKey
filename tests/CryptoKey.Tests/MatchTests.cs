using Xunit;
namespace CryptoKey.Tests;

public class MatchTests
{
    [Fact]
    public void Current_secret_on_any_letter_verifies()
    {
        string a = TestDisk.TempDir(), b = TestDisk.TempDir();
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig config = TestDisk.NewConfig(secret);
        TestDisk.WriteKeyfile(b, secret, config);

        KeyfileCheck check = KeyVerifier.Check(config, TestDisk.For(a, b));
        Assert.Equal(SecretMatch.Current, check.Match);
        Assert.Contains(b, check.MatchedLetters);
        Assert.Contains("verified", check.Detail);
    }

    [Fact]
    public void Previous_secret_reports_stale()
    {
        string a = TestDisk.TempDir();
        byte[] old = TestDisk.RandomSecret();
        KeyConfig config = TestDisk.NewConfig(old);
        // Rotate config forward in memory only — the drive still holds `old`,
        // which is now the previous generation.
        ConfigStore.RotateSecret(config, TestDisk.RandomSecret());
        TestDisk.WriteKeyfile(a, old, config);

        KeyfileCheck check = KeyVerifier.Check(config, TestDisk.For(a));
        Assert.Equal(SecretMatch.Previous, check.Match);
        Assert.Contains("stale", check.Detail);
    }

    [Fact]
    public void Current_on_one_letter_beats_previous_on_another()
    {
        string a = TestDisk.TempDir(), b = TestDisk.TempDir();
        byte[] old = TestDisk.RandomSecret(), cur = TestDisk.RandomSecret();
        KeyConfig config = TestDisk.NewConfig(old);
        ConfigStore.RotateSecret(config, cur); // cur current, old previous
        TestDisk.WriteKeyfile(a, old, config); // stale file on A
        TestDisk.WriteKeyfile(b, cur, config); // current on B

        KeyfileCheck check = KeyVerifier.Check(config, TestDisk.For(a, b));
        Assert.Equal(SecretMatch.Current, check.Match);
        Assert.Contains(a, check.MatchedLetters);
        Assert.Contains(b, check.MatchedLetters);
    }

    [Fact]
    public void Missing_keyfile_is_none_with_detail()
    {
        string a = TestDisk.TempDir();
        KeyConfig config = TestDisk.NewConfig(TestDisk.RandomSecret());
        KeyfileCheck check = KeyVerifier.Check(config, TestDisk.For(a));
        Assert.Equal(SecretMatch.None, check.Match);
        Assert.Contains("missing", check.Detail);
    }

    [Fact]
    public void No_letters_is_none()
    {
        KeyConfig config = TestDisk.NewConfig(TestDisk.RandomSecret());
        KeyfileCheck check = KeyVerifier.Check(config, TestDisk.For());
        Assert.Equal(SecretMatch.None, check.Match);
        Assert.Contains("no mounted volume", check.Detail);
    }

    [Fact]
    public void Wrong_secret_is_none()
    {
        string a = TestDisk.TempDir();
        KeyConfig config = TestDisk.NewConfig(TestDisk.RandomSecret());
        TestDisk.WriteKeyfile(a, TestDisk.RandomSecret(), config); // different secret
        Assert.Equal(SecretMatch.None, KeyVerifier.Check(config, TestDisk.For(a)).Match);
    }
}
