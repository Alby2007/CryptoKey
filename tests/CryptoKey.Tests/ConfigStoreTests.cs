using Xunit;
namespace CryptoKey.Tests;

/// <summary>
/// ConfigStore reads %APPDATA% once (static ConfigDir) — this fixture
/// redirects it to a temp dir before first access. Members of this
/// collection are the only tests that touch ConfigDir, so the redirect
/// can't race a parallel test that grabbed the real path first.
/// </summary>
public sealed class AppDataRedirectFixture : IDisposable
{
    public string Dir { get; } = Path.Combine(Path.GetTempPath(),
        "ckcfg-" + Guid.NewGuid().ToString("N"));

    public AppDataRedirectFixture()
    {
        Environment.SetEnvironmentVariable("APPDATA", Dir);
        // Fail loudly rather than write test data into the real profile:
        // if ConfigDir ever stops honoring the env redirect this throws
        // before any test can touch production config.json.
        if (!ConfigStore.ConfigDir.StartsWith(Dir, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                $"ConfigDir redirect failed — got {ConfigStore.ConfigDir}");
    }

    public void Dispose() { }
}

[CollectionDefinition("appdata-redirect")]
public sealed class AppDataCollection : ICollectionFixture<AppDataRedirectFixture> { }

[Collection("appdata-redirect")]
public class ConfigStoreTests
{
    private readonly AppDataRedirectFixture _fx;
    public ConfigStoreTests(AppDataRedirectFixture fx) => _fx = fx;

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
}
