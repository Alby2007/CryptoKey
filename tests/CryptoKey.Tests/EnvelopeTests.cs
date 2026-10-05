using System.Security.Cryptography;
using System.Text;
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

    // ------------------------------------------------- canon (CKY-ATTEST2)

    [Fact]
    public void Covered_guard_field_change_flags_mismatch()
    {
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig config = TestDisk.NewConfig(secret);
        byte[] file = KeyVerifier.WrapKeyfile(secret, config);

        // Watchdog is in the attest canon — a silent downgrade trips it.
        config.Guard.Watchdog = !config.Guard.Watchdog;
        Assert.True(KeyVerifier.TryUnwrapKeyfile(file, config,
            out _, out AttestState attest, out _));
        Assert.Equal(AttestState.Mismatch, attest);
    }

    [Theory]
    [InlineData("sounds")]
    [InlineData("balloon")]
    [InlineData("mountpoint")]
    [InlineData("size")]
    public void Excluded_fields_dont_trip_attestation(string which)
    {
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig config = TestDisk.NewConfig(secret);
        byte[] file = KeyVerifier.WrapKeyfile(secret, config);

        // Cosmetic/layout fields are deliberately outside the canon —
        // changing them must not force a re-attest.
        switch (which)
        {
            case "sounds": config.Guard.Sounds = !config.Guard.Sounds; break;
            case "balloon": config.Guard.BalloonTips = !config.Guard.BalloonTips; break;
            case "mountpoint": config.Guard.VaultMountPoint = "Q:"; break;
            case "size": config.Guard.VaultSizeMb = 1024; break;
        }
        Assert.True(KeyVerifier.TryUnwrapKeyfile(file, config,
            out _, out AttestState attest, out _));
        Assert.Equal(AttestState.Ok, attest);
    }

    [Fact]
    public void Legacy_attestation_form_still_verifies()
    {
        // Pre-canon keyfiles carry MAC = HMAC(secret, "CKY-ATTEST"‖serial‖
        // phraseHash) — hand-build that envelope; AttestMatches accepts it.
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig config = TestDisk.NewConfig(secret);
        byte[] attest = HMACSHA256.HashData(secret,
            Encoding.UTF8.GetBytes(
                "CKY-ATTEST" + config.DeviceSerial + config.PassphraseHash));
        byte[] plain = new byte[64 + 32];
        Buffer.BlockCopy(secret, 0, plain, 0, 64);
        Buffer.BlockCopy(attest, 0, plain, 64, 32);
        byte[] blob = Platform.Services.Protector.Protect(
            plain, KeyVerifier.ProtectorEntropy);
        byte[] file = new byte[4 + blob.Length];
        "CKY2"u8.ToArray().CopyTo(file, 0);
        Buffer.BlockCopy(blob, 0, file, 4, blob.Length);

        Assert.True(KeyVerifier.TryUnwrapKeyfile(file, config,
            out byte[]? back, out AttestState attestState, out _));
        Assert.Equal(secret, back);
        Assert.Equal(AttestState.Ok, attestState);
    }

    [Fact]
    public void Re_attest_heals_covered_field_change()
    {
        // File-level: wrap → covered edit → mismatch → RotateKeyfiles with a
        // fresh envelope (same secret, no generation burn) → Ok again.
        string letter = TestDisk.TempDir();
        try
        {
            byte[] secret = TestDisk.RandomSecret();
            KeyConfig config = TestDisk.NewConfig(secret);
            var disk = TestDisk.For(letter);
            TestDisk.WriteKeyfile(letter, secret, config);

            config.Guard.LockOnRemoval = false; // covered field — downgrade
            Assert.Equal(AttestState.Mismatch,
                KeyVerifier.Check(config, disk).Attest);

            var results = KeyVerifier.RotateKeyfiles(disk,
                KeyVerifier.WrapKeyfile(secret, config));
            Assert.All(results, r => Assert.Null(r.Error));
            Assert.Equal(AttestState.Ok, KeyVerifier.Check(config, disk).Attest);
        }
        finally
        {
            try { Directory.Delete(letter, recursive: true); } catch (Exception) { }
        }
    }

    [Fact]
    public void No_epoch_canon_still_verifies()
    {
        // Tier-1 keyfiles carry the canon without `vaultepoch` — the
        // three-candidate check must accept them, then the next write
        // silently upgrades to the epoch-included form.
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig config = TestDisk.NewConfig(secret);
        byte[] attest = ConfigStore.ComputeAttestNoEpoch(secret, config);
        byte[] plain = new byte[64 + 32];
        Buffer.BlockCopy(secret, 0, plain, 0, 64);
        Buffer.BlockCopy(attest, 0, plain, 64, 32);
        byte[] blob = Platform.Services.Protector.Protect(
            plain, KeyVerifier.ProtectorEntropy);
        byte[] file = new byte[4 + blob.Length];
        "CKY2"u8.ToArray().CopyTo(file, 0);
        Buffer.BlockCopy(blob, 0, file, 4, blob.Length);

        Assert.True(KeyVerifier.TryUnwrapKeyfile(file, config,
            out byte[]? back, out AttestState attestState, out _));
        Assert.Equal(secret, back);
        Assert.Equal(AttestState.Ok, attestState);
    }

    [Fact]
    public void Epoch_in_canon_trips_mismatch()
    {
        // VaultEpoch is canon-covered: a config whose epoch moved on from
        // the wrap-time value (e.g. replaced with an older copy) must
        // mismatch — that's what lets the vault catch a rolled-back image.
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig config = TestDisk.NewConfig(secret);
        config.VaultEpoch = 5;
        byte[] file = KeyVerifier.WrapKeyfile(secret, config);

        config.VaultEpoch = 6; // rolled back / diverged after the wrap
        // Still returns true — the caller needs the secret to re-attest.
        Assert.True(KeyVerifier.TryUnwrapKeyfile(file, config,
            out _, out AttestState attest, out _));
        Assert.Equal(AttestState.Mismatch, attest);

        config.VaultEpoch = 5; // restored — verifies again
        Assert.True(KeyVerifier.TryUnwrapKeyfile(file, config,
            out _, out attest, out _));
        Assert.Equal(AttestState.Ok, attest);
    }

    [Fact]
    public void Canon_is_deterministic_and_covering()
    {
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig a = TestDisk.NewConfig(secret);
        // Clone — NewConfig regenerates salts, which are themselves attested.
        KeyConfig b = System.Text.Json.JsonSerializer.Deserialize<KeyConfig>(
            System.Text.Json.JsonSerializer.Serialize(a))!;
        b.Guard.Animations = !a.Guard.Animations; // excluded — identical MAC
        Assert.Equal(ConfigStore.ComputeAttest(secret, a),
            ConfigStore.ComputeAttest(secret, b));
        b.Guard.IdleLockMinutes = 5; // covered — MAC must diverge
        Assert.NotEqual(ConfigStore.ComputeAttest(secret, a),
            ConfigStore.ComputeAttest(secret, b));
    }
}
