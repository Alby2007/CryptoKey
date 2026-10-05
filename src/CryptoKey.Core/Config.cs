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
    /// <summary>PBKDF2 verifier for the generated recovery phrase — see <see cref="RecoveryPhrase"/>.</summary>
    public string PassphraseHash { get; set; } = "";
    /// <summary>
    /// PBKDF2 rounds for <see cref="PassphraseHash"/>. Legacy configs carry
    /// 100k; anything written now uses the current OWASP floor (600k).
    /// Verify uses the stored count, regenerate rewrites it — old hashes keep
    /// verifying until the next phrase regeneration upgrades them.
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

/// <summary>How a verified key and the recovery phrase combine to unlock.</summary>
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

    /// <summary>Enable the encrypted vault (CKVAULT1 image → Dokan drive letter).</summary>
    public bool VaultEnabled { get; set; } = false;

    /// <summary>Mount automatically when the key verifies (off = mount via Vault page/CLI).</summary>
    public bool VaultAutoMount { get; set; } = true;

    /// <summary>Vault image path; "" = default (%LOCALAPPDATA%\CryptoKey\vault.ckv).</summary>
    public string VaultImagePath { get; set; } = "";

    /// <summary>Mount letter, "V:" form.</summary>
    public string VaultMountPoint { get; set; } = "V:";

    /// <summary>Created image size in MiB.</summary>
    public int VaultSizeMb { get; set; } = 256;

    /// <summary>Seal the vault (dismount + drop keys) after N idle minutes (0 = off).</summary>
    public int VaultIdleMinutes { get; set; } = 0;
}

internal static class ConfigStore
{
    private const int CurrentPbkdf2Iterations = 600_000;

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    // CRYPTOKEY_CONFIG_ROOT overrides the platform config dir — the test
    // suite uses it to redirect the store into a temp dir. A dedicated
    // variable rather than APPDATA itself: nothing else sets it, and a
    // set-but-empty value falls through instead of collapsing ConfigDir to
    // a relative path under the launcher's CWD.
    public static string ConfigDir =>
        Environment.GetEnvironmentVariable("CRYPTOKEY_CONFIG_ROOT") is { Length: > 0 } root
            ? root
            : Platform.Services.Paths.ConfigDir;

    public static string ConfigPath => Path.Combine(ConfigDir, "config.json");

    /// <summary>Last-good mirror written by every Save — Load falls back to it.</summary>
    public static string BackupPath => ConfigPath + ".bak";

    // Third copy, different kill surface: a folder wipe can't reach the
    // registry/plist backup, a backup delete can't reach the folder. Same
    // trust bar as .bak — only ever honored *after* the keyfile's own
    // attestation verifies, so a planted config still can't unlock anything.
    // Impl is per-platform (HKCU on Windows, plist file on macOS, temp in
    // tests) — swapped through Platform.Services.ConfigBackup.
    private static string? ReadBackup()
    {
        try { return Platform.Services.ConfigBackup.Read(); }
        catch (Exception) { return null; }
    }

    /// <summary>Set when the last Load came from the third-copy backup —
    /// means the config directory itself had been wiped. Callers log it louder.</summary>
    public static bool LastRestoreFromBackup { get; private set; }

    /// <summary>Can any copy of the config produce a usable Load?</summary>
    public static bool Resumable =>
        File.Exists(ConfigPath) || File.Exists(BackupPath)
        || ReadBackup() != null;

    public static KeyConfig? Load() => Load(out _);

    /// <summary>
    /// Load config. Chain: primary → .bak → third-copy backup. A corrupt
    /// primary is quarantined to config.json.bad; a missing file just falls
    /// through (covers folder wipes). A backup restore rewrites both
    /// files so the store self-heals, and flags <see cref="LastRestoreFromBackup"/>.
    /// Throws only when the primary was corrupt and NO backup parses.
    /// </summary>
    public static KeyConfig? Load(out bool restoredFromBackup)
    {
        restoredFromBackup = false;
        LastRestoreFromBackup = false;
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

        string? thirdCopy = ReadBackup();
        if (thirdCopy != null)
        {
            try
            {
                KeyConfig restored = Parse(thirdCopy);
                try
                {
                    Directory.CreateDirectory(ConfigDir);
                    AtomicFile.WriteAllText(ConfigPath, thirdCopy);
                    AtomicFile.WriteAllText(BackupPath, thirdCopy);
                }
                catch (Exception) { /* restore best-effort — the copy in hand still works */ }
                restoredFromBackup = true;
                LastRestoreFromBackup = true;
                return restored;
            }
            catch (Exception) { /* corrupt third copy — fall through */ }
        }

        if (primaryExisted)
            throw new InvalidDataException(
                $"Config at {ConfigPath} was corrupt and no backup (file or platform copy) is readable.");
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
        // Third copy into the platform store — best-effort; a denied write
        // must not fail the save.
        try { Platform.Services.ConfigBackup.Write(json); }
        catch (Exception) { }
    }

    public static KeyConfig CreateNew(string serial, byte[] secret, string recoveryPhrase)
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
                HashNormalized(recoveryPhrase, passSalt, CurrentPbkdf2Iterations)),
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

    public static void ChangePassphrase(KeyConfig config, string newRecoveryPhrase)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        config.PassphraseSalt = Convert.ToBase64String(salt);
        config.PassphraseHash = Convert.ToBase64String(
            HashNormalized(newRecoveryPhrase, salt, CurrentPbkdf2Iterations));
        config.PassphraseIterations = CurrentPbkdf2Iterations;
    }

    /// <summary>
    /// Verify a credential against the stored hash. Input is normalized
    /// first (<see cref="RecoveryPhrase.Normalize"/>), so a generated phrase
    /// verifies however the user managed to type it — and a legacy
    /// free-form passphrase fails against a phrase hash by design
    /// (force-migration; the enrolled key is the regeneration hatch).
    /// </summary>
    public static bool VerifyPassphrase(KeyConfig config, ReadOnlySpan<char> phrase)
    {
        // 64 chars covers any sane credential — anything that normalizes
        // past the buffer can't be the canonical phrase, so fail closed.
        Span<char> buf = stackalloc char[64];
        try
        {
            int n = RecoveryPhrase.Normalize(phrase, buf);
            if (n > buf.Length)
                return false;
            byte[] salt = Convert.FromBase64String(config.PassphraseSalt);
            byte[] expected = Convert.FromBase64String(config.PassphraseHash);
            byte[] derived = HashPassphrase(buf[..n], salt, config.PassphraseIterations);
            try
            {
                return CryptographicOperations.FixedTimeEquals(derived, expected);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(derived);
            }
        }
        catch (Exception)
        {
            return false; // corrupt or tampered config — never verify
        }
        finally
        {
            buf.Clear();
        }
    }

    /// <summary>
    /// Attestation MAC embedded in the v2 keyfile: the drive vouches that this
    /// config (serial + recovery-phrase hash + the security-relevant Guard
    /// fields) is the one the keyfile was written for. A mismatch means
    /// config.json or the keyfile was tampered with — the secret is required
    /// to forge the MAC, so an attacker who only copies/edits files can't
    /// produce one.
    /// </summary>
    public static byte[] ComputeAttest(byte[] secret, KeyConfig config)
    {
        byte[] data = Encoding.UTF8.GetBytes(
            "CKY-ATTEST2" + config.DeviceSerial + config.PassphraseHash
            + GuardCanonical(config));
        return HMACSHA256.HashData(secret, data);
    }

    /// <summary>
    /// Fixed-time compare against BOTH attestation forms: the extended
    /// canon (everything written now) and the legacy
    /// CKY-ATTEST‖serial‖phraseHash form (pre-canon keyfiles keep
    /// verifying — the next envelope write upgrades them silently).
    /// </summary>
    public static bool AttestMatches(byte[] secret, KeyConfig config,
        ReadOnlySpan<byte> stored)
        => CryptographicOperations.FixedTimeEquals(stored,
               ComputeAttest(secret, config))
           || CryptographicOperations.FixedTimeEquals(stored,
               LegacyAttest(secret, config));

    /// <summary>The pre-canon attestation input — kept for reads only.</summary>
    private static byte[] LegacyAttest(byte[] secret, KeyConfig config)
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

    /// <summary>
    /// Deterministic name=value canon over the security-relevant Guard
    /// fields — a silent downgrade in any of these trips the attestation.
    /// Cosmetic fields (Sounds, BalloonTips, Animations) and layout fields
    /// (VaultMountPoint/SizeMb/ImagePath) are deliberately absent: changing
    /// them must not force a re-attest. The hash-chain fields self-verify.
    /// </summary>
    private static string GuardCanonical(KeyConfig config)
    {
        GuardSettings g = config.Guard;
        static string B(bool v) => v ? "true" : "false";
        return "|unlockpolicy=" + (int)g.UnlockPolicy
            + "|stricttamper=" + B(g.StrictTamper)
            + "|lockmode=" + g.LockMode.ToLowerInvariant()
            + "|lockonremoval=" + B(g.LockOnRemoval)
            + "|watchdog=" + B(g.Watchdog)
            + "|lockpolicies=" + B(g.LockPolicies)
            + "|idlelockminutes=" + g.IdleLockMinutes
            + "|webcamontamper=" + B(g.WebcamOnTamper)
            + "|alerturl=" + g.AlertUrl.Trim()
            + "|vaultenabled=" + B(g.VaultEnabled)
            + "|vaultautomount=" + B(g.VaultAutoMount)
            + "|vaultidleminutes=" + g.VaultIdleMinutes
            + "|pollintervalms=" + g.PollIntervalMs;
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

    /// <summary>
    /// PBKDF2 over the normalized phrase — storage always holds the hash of
    /// the canonical uppercase form, and verify normalizes identically, so
    /// typed variants land on the same bytes.
    /// </summary>
    private static byte[] HashNormalized(ReadOnlySpan<char> phrase, byte[] salt, int iterations)
    {
        Span<char> buf = stackalloc char[64];
        try
        {
            int n = RecoveryPhrase.Normalize(phrase, buf);
            // Over-long input can't be a canonical phrase — refuse loudly
            // rather than hash a truncated prefix or an empty value.
            if (n > buf.Length)
                throw new ArgumentOutOfRangeException(nameof(phrase));
            return HashPassphrase(buf[..n], salt, iterations);
        }
        finally
        {
            buf.Clear();
        }
    }

    private static byte[] HashPassphrase(ReadOnlySpan<char> phrase, byte[] salt, int iterations)
        => Rfc2898DeriveBytes.Pbkdf2(phrase, salt, iterations, HashAlgorithmName.SHA256, 32);
}
