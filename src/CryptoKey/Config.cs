using System.Security.Cryptography;
using System.Text.Json;

namespace CryptoKey;

internal sealed class KeyConfig
{
    public int ConfigVersion { get; set; } = 1;
    public string DeviceSerial { get; set; } = "";
    public string SecretSalt { get; set; } = "";
    public string SecretHash { get; set; } = "";
    public string PassphraseSalt { get; set; } = "";
    public string PassphraseHash { get; set; } = "";
    public GuardSettings Guard { get; set; } = new();
}

internal sealed class GuardSettings
{
    public int PollIntervalMs { get; set; } = 1000;
    public bool LockOnRemoval { get; set; } = true;
    public bool BalloonTips { get; set; } = true;
    public bool Animations { get; set; } = true;
}

internal static class ConfigStore
{
    private const int Pbkdf2Iterations = 100_000;

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public static string ConfigDir { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "CryptoKey");

    public static string ConfigPath => Path.Combine(ConfigDir, "config.json");

    public static KeyConfig? Load()
    {
        if (!File.Exists(ConfigPath))
            return null;
        KeyConfig? config = JsonSerializer.Deserialize<KeyConfig>(File.ReadAllText(ConfigPath));
        if (config != null)
            config.Guard ??= new GuardSettings();
        return config;
    }

    public static void Save(KeyConfig config)
    {
        Directory.CreateDirectory(ConfigDir);
        File.WriteAllText(ConfigPath, JsonSerializer.Serialize(config, JsonOptions));
    }

    public static KeyConfig CreateNew(string serial, byte[] secret, string passphrase)
    {
        byte[] secretSalt = RandomNumberGenerator.GetBytes(16);
        byte[] passSalt = RandomNumberGenerator.GetBytes(16);
        return new KeyConfig
        {
            DeviceSerial = serial,
            SecretSalt = Convert.ToBase64String(secretSalt),
            SecretHash = Convert.ToBase64String(HashSecret(secret, secretSalt)),
            PassphraseSalt = Convert.ToBase64String(passSalt),
            PassphraseHash = Convert.ToBase64String(HashPassphrase(passphrase, passSalt)),
        };
    }

    public static bool VerifySecret(KeyConfig config, byte[] secret)
    {
        try
        {
            byte[] salt = Convert.FromBase64String(config.SecretSalt);
            byte[] expected = Convert.FromBase64String(config.SecretHash);
            return CryptographicOperations.FixedTimeEquals(HashSecret(secret, salt), expected);
        }
        catch (Exception)
        {
            return false; // corrupt or tampered config — never verify
        }
    }

    public static void ChangePassphrase(KeyConfig config, string newPassphrase)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        config.PassphraseSalt = Convert.ToBase64String(salt);
        config.PassphraseHash = Convert.ToBase64String(HashPassphrase(newPassphrase, salt));
    }

    public static bool VerifyPassphrase(KeyConfig config, string passphrase)
    {
        try
        {
            byte[] salt = Convert.FromBase64String(config.PassphraseSalt);
            byte[] expected = Convert.FromBase64String(config.PassphraseHash);
            return CryptographicOperations.FixedTimeEquals(HashPassphrase(passphrase, salt), expected);
        }
        catch (Exception)
        {
            return false; // corrupt or tampered config — never verify
        }
    }

    // The on-disk secret is 64 random bytes — high entropy, so a single
    // salted SHA-256 is a sufficient verifier.
    private static byte[] HashSecret(byte[] secret, byte[] salt)
    {
        byte[] combined = new byte[salt.Length + secret.Length];
        Buffer.BlockCopy(salt, 0, combined, 0, salt.Length);
        Buffer.BlockCopy(secret, 0, combined, salt.Length, secret.Length);
        return SHA256.HashData(combined);
    }

    private static byte[] HashPassphrase(string passphrase, byte[] salt)
        => Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, Pbkdf2Iterations, HashAlgorithmName.SHA256, 32);
}
