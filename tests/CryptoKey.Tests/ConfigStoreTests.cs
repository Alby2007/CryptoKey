using Xunit;
namespace CryptoKey.Tests;

/// <summary>
/// ConfigDir is redirected to a per-run temp dir by TestInit's module
/// initializer — these tests exercise the real store, just never the
/// real profile.
/// </summary>
public class ConfigStoreTests
{
    [Fact]
    public void Save_load_round_trip()
    {
        KeyConfig config = ConfigStore.CreateNew("SER-123",
            TestDisk.RandomSecret(), "a test passphrase");
        config.Guard.UnlockPolicy = UnlockPolicy.KeyAndPassphrase;
        config.Guard.Watchdog = false;
        ConfigStore.Save(config);

        KeyConfig? loaded = ConfigStore.Load();
        Assert.NotNull(loaded);
        Assert.Equal("SER-123", loaded.DeviceSerial);
        Assert.Equal(config.SecretHash, loaded.SecretHash);
        Assert.Equal(UnlockPolicy.KeyAndPassphrase, loaded.Guard.UnlockPolicy);
        Assert.False(loaded.Guard.Watchdog);
    }

    [Fact]
    public void Save_leaves_no_tmp_file()
    {
        ConfigStore.Save(ConfigStore.CreateNew("S", TestDisk.RandomSecret(), "pp"));
        Assert.False(File.Exists(ConfigStore.ConfigPath + ".tmp"));
    }

    [Fact]
    public void MatchSecret_tri_state_is_consistent_with_RotateSecret()
    {
        byte[] genA = TestDisk.RandomSecret(), genB = TestDisk.RandomSecret(),
               alien = TestDisk.RandomSecret();
        KeyConfig config = ConfigStore.CreateNew("S", genA, "pp");

        Assert.Equal(SecretMatch.Current, ConfigStore.MatchSecret(config, genA));
        Assert.Equal(SecretMatch.None, ConfigStore.MatchSecret(config, alien));

        ConfigStore.RotateSecret(config, genB);
        Assert.Equal(SecretMatch.Current, ConfigStore.MatchSecret(config, genB));
        Assert.Equal(SecretMatch.Previous, ConfigStore.MatchSecret(config, genA));
        Assert.Equal(SecretMatch.None, ConfigStore.MatchSecret(config, alien));
    }

    [Fact]
    public void Corrupt_config_hashes_never_verify()
    {
        KeyConfig config = ConfigStore.CreateNew("S", TestDisk.RandomSecret(), "pp");
        config.SecretHash = "!!!not-base64!!!";
        Assert.Equal(SecretMatch.None,
            ConfigStore.MatchSecret(config, TestDisk.RandomSecret()));
    }

    [Fact]
    public void Passphrase_verify_and_change()
    {
        KeyConfig config = ConfigStore.CreateNew("S", TestDisk.RandomSecret(), "first-pass");
        Assert.True(ConfigStore.VerifyPassphrase(config, "first-pass"));
        Assert.False(ConfigStore.VerifyPassphrase(config, "wrong"));

        ConfigStore.ChangePassphrase(config, "second-pass");
        Assert.True(ConfigStore.VerifyPassphrase(config, "second-pass"));
        Assert.False(ConfigStore.VerifyPassphrase(config, "first-pass"));
    }

    [Fact]
    public void Corrupt_primary_falls_back_to_bak_and_quarantines()
    {
        KeyConfig config = ConfigStore.CreateNew("SER-BAK",
            TestDisk.RandomSecret(), "pp");
        ConfigStore.Save(config);

        File.WriteAllText(ConfigStore.ConfigPath, "{ not json at all");
        KeyConfig? loaded = ConfigStore.Load(out bool fromBackup);

        Assert.True(fromBackup);
        Assert.NotNull(loaded);
        Assert.Equal("SER-BAK", loaded.DeviceSerial);
        Assert.Equal(config.SecretHash, loaded.SecretHash);
        // The corrupt file is kept for forensics, not silently overwritten.
        Assert.True(File.Exists(ConfigStore.ConfigPath + ".bad"));
    }

    [Fact]
    public void All_copies_dead_throws()
    {
        ConfigStore.Save(ConfigStore.CreateNew("S", TestDisk.RandomSecret(), "pp"));
        File.WriteAllText(ConfigStore.ConfigPath, "{ bad");
        File.WriteAllText(ConfigStore.BackupPath, "{ also bad");
        DeleteRegistryBackup();
        Assert.ThrowsAny<Exception>(() => ConfigStore.Load());
    }

    [Fact]
    public void Corrupt_files_fall_through_to_registry()
    {
        // The registry copy exists precisely for the both-files-dead case —
        // a corrupt .bak must not end the chain before it's tried.
        ConfigStore.Save(ConfigStore.CreateNew("SER-REG", TestDisk.RandomSecret(), "pp"));
        File.WriteAllText(ConfigStore.ConfigPath, "{ bad");
        File.WriteAllText(ConfigStore.BackupPath, "{ also bad");

        KeyConfig? loaded = ConfigStore.Load(out bool fromBackup);

        Assert.NotNull(loaded);
        Assert.True(fromBackup);
        Assert.True(ConfigStore.LastRestoreFromRegistry);
        Assert.Equal("SER-REG", loaded!.DeviceSerial);
        // Both files got re-created from the registry copy.
        Assert.True(File.Exists(ConfigStore.ConfigPath));
        Assert.True(File.Exists(ConfigStore.BackupPath));
    }

    [Fact]
    public void Folder_wipe_restores_from_registry()
    {
        ConfigStore.Save(ConfigStore.CreateNew("SER-WIPE", TestDisk.RandomSecret(), "pp"));
        Directory.Delete(ConfigStore.ConfigDir, recursive: true);

        KeyConfig? loaded = ConfigStore.Load(out _);

        Assert.Equal("SER-WIPE", loaded!.DeviceSerial);
        Assert.True(ConfigStore.LastRestoreFromRegistry);
        Assert.True(File.Exists(ConfigStore.ConfigPath));
    }

    [Fact]
    public void Corrupt_registry_copy_falls_to_throw()
    {
        ConfigStore.Save(ConfigStore.CreateNew("S", TestDisk.RandomSecret(), "pp"));
        File.WriteAllText(ConfigStore.ConfigPath, "{ bad");
        File.WriteAllText(ConfigStore.BackupPath, "{ also bad");
        using (var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(ConfigStore.RegKeyPath))
            key.SetValue("Config", "{ corrupt json");
        Assert.ThrowsAny<Exception>(() => ConfigStore.Load());
    }

    private static void DeleteRegistryBackup()
    {
        Microsoft.Win32.Registry.CurrentUser.DeleteSubKeyTree(
            ConfigStore.RegKeyPath, throwOnMissingSubKey: false);
    }

    [Fact]
    public void Passphrase_iterations_upgrade_on_change()
    {
        KeyConfig config = ConfigStore.CreateNew("S", TestDisk.RandomSecret(), "pass-one");
        Assert.Equal(600_000, config.PassphraseIterations);

        // A legacy 100k hash keeps verifying under its own count — the
        // stored hash is of the normalized form ("PASSONE"), which is how
        // every phrase credential is written now.
        byte[] salt = Convert.FromBase64String(config.PassphraseSalt);
        config.PassphraseIterations = 100_000;
        config.PassphraseHash = Convert.ToBase64String(
            System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2(
                "PASSONE", salt, 100_000,
                System.Security.Cryptography.HashAlgorithmName.SHA256, 32));
        Assert.True(ConfigStore.VerifyPassphrase(config, "pass-one"));

        // …and the next change rewrites at the current work factor.
        ConfigStore.ChangePassphrase(config, "pass-two");
        Assert.Equal(600_000, config.PassphraseIterations);
        Assert.True(ConfigStore.VerifyPassphrase(config, "pass-two"));
    }
}
