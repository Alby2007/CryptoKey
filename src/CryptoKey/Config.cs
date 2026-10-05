using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CryptoKey;

internal sealed class KeyConfig
{
    /// <summary>Failsafe-passphrase floor at enroll/change — verification accepts any length.</summary>
    public const int MinPassphraseLength = 8;

    public int ConfigVersion { get; set; } = 1;
    public string DeviceSerial { get; set; } = "";
    public string SecretSalt { get; set; } = "";
    public string SecretHash { get; set; } = "";
    public string PrevSecretHash { get; set; } = "";
    public int RotationCount { get; set; } = 1;
    public DateTime? LastRotationUtc { get; set; }
    public string PassphraseSalt { get; set; } = "";
    public string PassphraseHash { get; set; } = "";
    /// <summary>
    /// PBKDF2 rounds for <see cref="PassphraseHash"/>. Legacy configs carry
    /// 100k; anything written now uses the current OWASP floor (600k).
    /// Verify uses the stored count, change rewrites it — old hashes keep
    /// verifying until the next passphrase change upgrades them.
    /// </summary>
    public int PassphraseIterations { get; set; } = 100_000;
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
    /// <summary>Lock/unlock/tamper sound cues (synthesized — Sounds.cs).</summary>
    public bool Sounds { get; set; } = true;
    [JsonConverter(typeof(JsonStringEnumConverter<UnlockPolicy>))]
    public UnlockPolicy UnlockPolicy { get; set; } = UnlockPolicy.KeyOrPassphrase;

    /// <summary>Stale (previous-generation) keyfiles never count as the key factor.</summary>
    public bool StrictTamper { get; set; }

    /// <summary>"secure" (default) → private-desktop lock; "overlay" → classic.</summary>
    public string LockMode { get; set; } = "secure";

    /// <summary>Persistent supervisor respawns the guard on ungraceful death.</summary>
    public bool Watchdog { get; set; } = true;

    /// <summary>Hide Task Manager/sign-out/power affordances while locked.</summary>
    public bool LockPolicies { get; set; } = true;

    /// <summary>Auto-lock after N minutes of no input (0 = off).</summary>
    public int IdleLockMinutes { get; set; } = 0;

    /// <summary>Snapshot the webcam on tamper events (privacy opt-in).</summary>
    public bool WebcamOnTamper { get; set; } = false;

    /// <summary>POST target for security events — ntfy.sh topic or any webhook ("" = off).</summary>
    public string AlertUrl { get; set; } = "";
}

internal static class ConfigStore
{
    private const int CurrentPbkdf2Iterations = 600_000;

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    // CRYPTOKEY_CONFIG_ROOT overrides the profile root — the test suite
    // uses it to redirect the store into a temp dir. A dedicated variable
    // rather than APPDATA itself: nothing else sets it, and a set-but-
    // empty value falls through instead of collapsing ConfigDir to a
    // relative path under the launcher's CWD.
    public static string ConfigDir { get; } = Path.Combine(
        Environment.GetEnvironmentVariable("CRYPTOKEY_CONFIG_ROOT") is { Length: > 0 } root
            ? root
            : Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "CryptoKey");

    public static string ConfigPath => Path.Combine(ConfigDir, "config.json");

    /// <summary>Last-good mirror written by every Save — Load falls back to it.</summary>
    public static string BackupPath => ConfigPath + ".bak";

    // Third copy, different kill surface: a folder wipe can't reach the
    // registry, a registry delete can't reach the folder. Same trust bar
    // as .bak — only ever honored *after* the keyfile's own attestation
    // verifies, so a planted config still can't unlock anything.
    // Mutable so tests can redirect it — without that seam, every Save in
    // a test writes into the user's real HKCU backup.
    internal static string RegKeyPath = @"Software\CryptoKey";
    private const string RegValueName = "Config";

    /// <summary>Set when the last Load came from the registry — means the
    /// config directory itself had been wiped. Callers log it louder.</summary>
    public static bool LastRestoreFromRegistry { get; private set; }

    /// <summary>Can any copy of the config produce a usable Load?</summary>
    public static bool Resumable =>
        File.Exists(ConfigPath) || File.Exists(BackupPath)
        || ReadRegistryBackup() != null;

    private static string? ReadRegistryBackup()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(RegKeyPath);
            return key?.GetValue(RegValueName) as string;
        }
        catch (Exception)
        {
            return null;
        }
    }

    public static KeyConfig? Load() => Load(out _);

    /// <summary>
    /// Load config. Chain: primary → .bak → registry backup. A corrupt
    /// primary is quarantined to config.json.bad; a missing file just falls
    /// through (covers folder wipes). A registry restore rewrites both
    /// files so the store self-heals, and flags <see cref="LastRestoreFromRegistry"/>.
    /// Throws only when the primary was corrupt and NO backup parses.
    /// </summary>
    public static KeyConfig? Load(out bool restoredFromBackup)
    {
        restoredFromBackup = false;
        LastRestoreFromRegistry = false;
        bool primaryExisted = File.Exists(ConfigPath);
        if (primaryExisted)
        {
            try
            {
                return Parse(File.ReadAllText(ConfigPath));
            }
            catch (Exception)
            {
                try { File.Move(ConfigPath, ConfigPath + ".bad", overwrite: true); }
                catch (Exception) { }
            }
        }

        if (File.Exists(BackupPath))
        {
            try
            {
                KeyConfig backup = Parse(File.ReadAllText(BackupPath));
                restoredFromBackup = true;
                return backup;
            }
            catch (Exception)
            {
                // Corrupt .bak must NOT end the chain — the registry copy
                // exists precisely for the both-files-dead case.
                try { File.Move(BackupPath, BackupPath + ".bad", overwrite: true); }
                catch (Exception) { }
            }
        }

        string? reg = ReadRegistryBackup();
        if (reg != null)
        {
            try
            {
                KeyConfig restored = Parse(reg);
                try
                {
                    Directory.CreateDirectory(ConfigDir);
                    AtomicFile.WriteAllText(ConfigPath, reg);
                    AtomicFile.WriteAllText(BackupPath, reg);
                }
                catch (Exception) { /* restore best-effort — the copy in hand still works */ }
                restoredFromBackup = true;
                LastRestoreFromRegistry = true;
                return restored;
            }
            catch (Exception) { /* corrupt registry copy — fall through */ }
        }

        if (primaryExisted)
            throw new InvalidDataException(
                $"Config at {ConfigPath} was corrupt and no backup (file or registry) is readable.");
        return null;
    }

    private static KeyConfig Parse(string json)
    {
        KeyConfig? config = JsonSerializer.Deserialize<KeyConfig>(json);
        if (config == null)
            throw new InvalidDataException("Config payload was empty.");
        config.Guard ??= new GuardSettings();
        return config;
    }

    public static void Save(KeyConfig config)
    {
        Directory.CreateDirectory(ConfigDir);
        string json = JsonSerializer.Serialize(config, JsonOptions);
        AtomicFile.WriteAllText(ConfigPath, json);
        // The backup is written durably too — a torn .bak is no better
        // than none when it's the file that covers a torn primary.
        AtomicFile.WriteAllText(BackupPath, json);
        // Third copy into the registry — best-effort; a denied HKCU write
        // must not fail the save.
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(RegKeyPath);
            key.SetValue(RegValueName, json);
        }
        catch (Exception) { }
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
            PassphraseHash = Convert.ToBase64String(
                HashPassphrase(passphrase, passSalt, CurrentPbkdf2Iterations)),
            PassphraseIterations = CurrentPbkdf2Iterations,
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
        config.PassphraseHash = Convert.ToBase64String(
            HashPassphrase(newPassphrase, salt, CurrentPbkdf2Iterations));
        config.PassphraseIterations = CurrentPbkdf2Iterations;
    }

    public static bool VerifyPassphrase(KeyConfig config, string passphrase)
    {
        try
        {
            byte[] salt = Convert.FromBase64String(config.PassphraseSalt);
            byte[] expected = Convert.FromBase64String(config.PassphraseHash);
            return CryptographicOperations.FixedTimeEquals(
                HashPassphrase(passphrase, salt, config.PassphraseIterations), expected);
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

    private static byte[] HashPassphrase(string passphrase, byte[] salt, int iterations)
        => Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, iterations, HashAlgorithmName.SHA256, 32);
}
