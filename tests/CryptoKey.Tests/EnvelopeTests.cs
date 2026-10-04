using Xunit;
namespace CryptoKey.Tests;

public class EnvelopeTests
{
    [Fact]
    public void Wrap_unwrap_round_trip()
    {
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig config = TestDisk.NewConfig(secret);
        byte[] file = KeyVerifier.WrapKeyfile(secret, config);

        Assert.True(file.AsSpan(0, 4).SequenceEqual("CKY2"u8));
        Assert.True(KeyVerifier.TryUnwrapKeyfile(file, config,
            out byte[]? back, out AttestState attest, out string detail));
        Assert.Equal(secret, back);
        Assert.Equal(AttestState.Ok, attest);
        Assert.Equal("attested", detail);
    }

    [Fact]
    public void Legacy_64_byte_file_is_pre_attestation()
    {
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig config = TestDisk.NewConfig(secret);
        Assert.True(KeyVerifier.TryUnwrapKeyfile(secret, config,
            out byte[]? back, out AttestState attest, out _));
        Assert.Equal(secret, back);
        Assert.Equal(AttestState.Missing, attest);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    [InlineData(4)]  // magic only, no blob
    [InlineData(63)] // just under legacy length
    public void Malformed_files_rejected(int length)
    {
        KeyConfig config = TestDisk.NewConfig(TestDisk.RandomSecret());
        Assert.False(KeyVerifier.TryUnwrapKeyfile(new byte[length], config,
            out _, out _, out _));
    }

    [Fact]
    public void Bad_magic_rejected()
    {
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig config = TestDisk.NewConfig(secret);
        byte[] file = KeyVerifier.WrapKeyfile(secret, config);
        file[0] = (byte)'X';
        Assert.False(KeyVerifier.TryUnwrapKeyfile(file, config, out _, out _, out _));
    }

    [Fact]
    public void Corrupted_blob_rejected()
    {
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig config = TestDisk.NewConfig(secret);
        byte[] file = KeyVerifier.WrapKeyfile(secret, config);
        file[^1] ^= 0xFF; // flip a byte inside the DPAPI blob
        Assert.False(KeyVerifier.TryUnwrapKeyfile(file, config, out _, out _, out _));
    }

    [Fact]
    public void Passphrase_hash_change_flags_attest_mismatch()
    {
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig config = TestDisk.NewConfig(secret);
        byte[] file = KeyVerifier.WrapKeyfile(secret, config);

        // Simulate config.json tampering — the MAC inside the envelope
        // covers the passphrase hash, so changing it trips the wire while
        // the secret still unwraps.
        ConfigStore.ChangePassphrase(config, "a-different-passphrase");
        Assert.True(KeyVerifier.TryUnwrapKeyfile(file, config,
            out byte[]? back, out AttestState attest, out _));
        Assert.Equal(secret, back);
        Assert.Equal(AttestState.Mismatch, attest);
    }
}
