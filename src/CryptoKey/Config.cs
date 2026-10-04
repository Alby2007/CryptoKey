using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CryptoKey;

internal sealed class KeyConfig
{
    public int ConfigVersion { get; set; } = 1;
    public string DeviceSerial { get; set; } = "";
    public string SecretSalt { get; set; } = "";
    public string SecretHash { get; set; } = "";
    public string PrevSecretHash { get; set; } = "";
    public int RotationCount { get; set; } = 1;
    public DateTime? LastRotationUtc { get; set; }
    public string PassphraseSalt { get; set; } = "";
    public string PassphraseHash { get; set; } = "";
    public GuardSettings Guard { get; set; } = new();
}

internal enum SecretMatch
{
    None,
    Current,
    Previous,
}

/// <summary>How a verified key and the failsafe passphrase combine to unlock.</summary>
internal enum UnlockPolicy
{
    KeyOrPassphrase,
    KeyAndPassphrase,
    KeyOnly,
}

/// <summary>Whether the keyfile's embedded config attestation matched.</summary>
internal enum AttestState
{
    Ok,
    Missing,
    Mismatch,
}

internal sealed class GuardSettings
{
    public int PollIntervalMs { get; set; } = 1000;
    public bool LockOnRemoval { get; set; } = true;
    public bool BalloonTips { get; set; } = true;
    public bool Animations { get; set; } = true;
    [JsonConverter(typeof(JsonStringEnumConverter<UnlockPolicy>))]
    public UnlockPolicy UnlockPolicy { get; set; } = UnlockPolicy.KeyOrPassphrase;

    /// <summary>Stale (previous-generation) keyfiles never count as the key factor.</summary>
    public bool StrictTamper { get; set; }

    /// <summary>"secure" (default) → private-desktop lock; "overlay" → classic.</summary>
    public string LockMode { get; set; } = "secure";

    /// <summary>Persistent supervisor respawns the guard on ungraceful death.</summary>
    public bool Watchdog { get; set; } = true;
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
        string tmp = ConfigPath + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(config, JsonOptions));
        File.Move(tmp, ConfigPath, overwrite: true);
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
            RotationCount = 1,
            PassphraseSalt = Convert.ToBase64String(passSalt),
            PassphraseHash = Convert.ToBase64String(HashPassphrase(passphrase, passSalt)),
        };
    }

    public static bool VerifySecret(KeyConfig config, byte[] secret)
        => MatchSecret(config, secret) == SecretMatch.Current;

    /// <summary>
    /// Current hash wins; a match only against the previous generation is
    /// <see cref="SecretMatch.Previous"/> — still accepted (interrupted
    /// rotation) but reported so the caller can flag it as a possible clone.
    /// </summary>
    public static SecretMatch MatchSecret(KeyConfig config, byte[] secret)
    {
        try
        {
            byte[] salt = Convert.FromBase64String(config.SecretSalt);
            byte[] hash = HashSecret(secret, salt);
            if (CryptographicOperations.FixedTimeEquals(hash,
                    Convert.FromBase64String(config.SecretHash)))
                return SecretMatch.Current;
            if (config.PrevSecretHash.Length > 0
                && CryptographicOperations.FixedTimeEquals(hash,
                    Convert.FromBase64String(config.PrevSecretHash)))
                return SecretMatch.Previous;
            return SecretMatch.None;
        }
        catch (Exception)
        {
            return SecretMatch.None; // corrupt or tampered config — never verify
        }
    }

    /// <summary>
    /// Shifts the hash chain one generation forward. When the rotation was
    /// triggered by a previous-generation (stale) keyfile, <paramref name="keepPrev"/>
    /// pins the chain: the drive still holds that generation, so shifting prev
    /// past it would permanently disown the drive if this rotation's keyfile
    /// write fails — pinned, a failed write just retries next check.
    /// </summary>
    public static void RotateSecret(KeyConfig config, byte[] newSecret, bool keepPrev = false)
    {
        if (!keepPrev)
            config.PrevSecretHash = config.SecretHash;
        byte[] salt = Convert.FromBase64String(config.SecretSalt);
        config.SecretHash = Convert.ToBase64String(HashSecret(newSecret, salt));
        config.RotationCount++;
        config.LastRotationUtc = DateTime.UtcNow;
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

    /// <summary>
    /// Attestation MAC embedded in the v2 keyfile: the drive vouches that this
    /// config (serial + passphrase hash) is the one the keyfile was written
    /// for. A mismatch means config.json or the keyfile was tampered with —
    /// the secret is required to forge the MAC, so an attacker who only
    /// copies/edits files can't produce one.
    /// </summary>
    public static byte[] ComputeAttest(byte[] secret, KeyConfig config)
    {
        byte[] tag = Encoding.UTF8.GetBytes("CKY-ATTEST");
        byte[] serial = Encoding.UTF8.GetBytes(config.DeviceSerial);
        byte[] pass = Encoding.UTF8.GetBytes(config.PassphraseHash);
        byte[] data = new byte[tag.Length + serial.Length + pass.Length];
        Buffer.BlockCopy(tag, 0, data, 0, tag.Length);
        Buffer.BlockCopy(serial, 0, data, tag.Length, serial.Length);
        Buffer.BlockCopy(pass, 0, data, tag.Length + serial.Length, pass.Length);
        return HMACSHA256.HashData(secret, data);
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
