using Xunit;

namespace CryptoKey.Tests;

/// <summary>
/// H3 — keyfile reads are bounded: a hostile device answering our serial
/// can't stall the engine (or starve the input hooks) with a giant or
/// never-ending `.cryptokey`. The size cap is asserted here; the timeout
/// thread is exercised implicitly by every existing verify test.
/// </summary>
public class KeyfileReadBoundTests
{
    [Fact]
    public void Oversized_keyfile_is_refused_not_read()
    {
        string dir = TestDisk.TempDir();
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig config = TestDisk.NewConfig(secret);
        File.WriteAllBytes(KeyVerifier.KeyFilePath(dir), new byte[8192]);

        KeyfileCheck check = KeyVerifier.Check(config, TestDisk.For(dir));

        Assert.Equal(SecretMatch.None, check.Match);
        Assert.Contains("oversized", check.Detail);
    }

    [Fact]
    public void Normal_envelope_still_verifies_under_the_cap()
    {
        string dir = TestDisk.TempDir();
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig config = TestDisk.NewConfig(secret);
        TestDisk.WriteKeyfile(dir, secret, config);

        KeyfileCheck check = KeyVerifier.Check(config, TestDisk.For(dir));

        Assert.Equal(SecretMatch.Current, check.Match);
    }
}
