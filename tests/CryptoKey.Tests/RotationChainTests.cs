using Xunit;
namespace CryptoKey.Tests;

/// <summary>
/// The ratchet invariant: a config-side rotation must never orphan the
/// drive. RotateSecret with no drive write leaves the drive Previous
/// (heal window); a completed write lands Current. keepPrev pins the chain
/// so a failed write on a stale drive stays healable instead of being
/// disowned two generations deep.
/// </summary>
public class RotationChainTests
{
    [Fact]
    public void Rotate_without_write_leaves_drive_stale_then_heals()
    {
        string letter = TestDisk.TempDir();
        byte[] genA = TestDisk.RandomSecret();
        KeyConfig config = TestDisk.NewConfig(genA);
        TestDisk.WriteKeyfile(letter, genA, config);

        // Burn: config rotates, drive not yet written → Previous (heal window).
        byte[] genB = TestDisk.RandomSecret();
        ConfigStore.RotateSecret(config, genB);
        KeyfileCheck mid = KeyVerifier.Check(config, TestDisk.For(letter));
        Assert.Equal(SecretMatch.Previous, mid.Match);

        // Drive write lands → Current.
        KeyVerifier.RotateKeyfiles(TestDisk.For(letter),
            KeyVerifier.WrapKeyfile(genB, config));
        Assert.Equal(SecretMatch.Current,
            KeyVerifier.Check(config, TestDisk.For(letter)).Match);
    }

    [Fact]
    public void KeepPrev_pins_stale_drive_against_failed_write()
    {
        string letter = TestDisk.TempDir();
        byte[] genA = TestDisk.RandomSecret(), genB = TestDisk.RandomSecret();
        KeyConfig config = TestDisk.NewConfig(genA);
        ConfigStore.RotateSecret(config, genB);            // config: cur=B prev=A
        TestDisk.WriteKeyfile(letter, genA, config);       // drive still holds A

        // Stale drive triggers another rotation; keepPrev keeps A as prev —
        // the write "fails" (we never write), and A must still verify stale.
        ConfigStore.RotateSecret(config, TestDisk.RandomSecret(), keepPrev: true);
        Assert.Equal(SecretMatch.Previous,
            KeyVerifier.Check(config, TestDisk.For(letter)).Match);
    }

    [Fact]
    public void Without_keepPrev_failed_write_orphans_stale_drive()
    {
        string letter = TestDisk.TempDir();
        byte[] genA = TestDisk.RandomSecret(), genB = TestDisk.RandomSecret();
        KeyConfig config = TestDisk.NewConfig(genA);
        ConfigStore.RotateSecret(config, genB);
        TestDisk.WriteKeyfile(letter, genA, config);

        // No keepPrev: prev shifts to B — drive's A matches nothing.
        ConfigStore.RotateSecret(config, TestDisk.RandomSecret(), keepPrev: false);
        Assert.Equal(SecretMatch.None,
            KeyVerifier.Check(config, TestDisk.For(letter)).Match);
    }

    [Fact]
    public void Full_chain_survives_repeated_rotations()
    {
        string letter = TestDisk.TempDir();
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig config = TestDisk.NewConfig(secret);
        TestDisk.WriteKeyfile(letter, secret, config);
        UsbDisk disk = TestDisk.For(letter);

        for (int i = 0; i < 5; i++)
        {
            Assert.Equal(SecretMatch.Current, KeyVerifier.Check(config, disk).Match);
            byte[] next = TestDisk.RandomSecret();
            ConfigStore.RotateSecret(config, next);
            KeyVerifier.RotateKeyfiles(disk, KeyVerifier.WrapKeyfile(next, config));
        }
        Assert.Equal(6, config.RotationCount);
        Assert.Equal(SecretMatch.Current, KeyVerifier.Check(config, disk).Match);
    }
}
