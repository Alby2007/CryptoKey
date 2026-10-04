using System.Security.Cryptography;
using System.Text;

namespace CryptoKey;

/// <summary>Result of checking a mounted device's keyfile against the config.</summary>
internal sealed record KeyfileCheck(
    SecretMatch Match,
    string Detail,
    IReadOnlyList<string> MatchedLetters,
    AttestState Attest);

internal static class KeyVerifier
{
    public const string KeyFileName = ".cryptokey";

    /// <summary>v2 envelope: magic || DPAPI(secret[64] || attest[32]).</summary>
    private static readonly byte[] Magic = "CKY2"u8.ToArray();
    private static readonly byte[] DpapiEntropy = Encoding.UTF8.GetBytes("CryptoKey.v2");
    private const int SecretLen = 64;
    private const int AttestLen = 32;

    public static string KeyFilePath(string driveLetter)
        => Path.Combine(driveLetter + "\\", KeyFileName);

    /// <summary>
    /// True when the enrolled device is present AND its keyfile secret
    /// verifies against the current or previous generation hash. Never
    /// throws — failures mean "not verified", so callers fail closed.
    /// </summary>
    public static bool Verify(KeyConfig config, out string detail)
    {
        UsbDisk? disk;
        try
        {
            disk = UsbMonitor.FindDisk(config.DeviceSerial);
        }
        catch (Exception ex)
        {
            detail = $"device enumeration failed: {ex.Message}";
            return false;
        }
        if (disk == null)
        {
            detail = "enrolled device not present";
            return false;
        }
        return Verify(config, disk, out detail);
    }

    /// <summary>Verify a device the caller already located (skips re-enumeration).</summary>
    public static bool Verify(KeyConfig config, UsbDisk disk, out string detail)
    {
        KeyfileCheck check = Check(config, disk);
        detail = check.Detail;
        return check.Match != SecretMatch.None;
    }

    /// <summary>
    /// Wraps a secret into the v2 keyfile envelope: DPAPI-bound to this
    /// user+machine, carrying the config attestation MAC inside the protected
    /// blob so a copied file is dead weight off this machine.
    /// </summary>
    public static byte[] WrapKeyfile(byte[] secret, KeyConfig config)
    {
        byte[] plain = new byte[SecretLen + AttestLen];
        Buffer.BlockCopy(secret, 0, plain, 0, SecretLen);
        Buffer.BlockCopy(ConfigStore.ComputeAttest(secret, config), 0, plain, SecretLen, AttestLen);
        byte[] blob = ProtectedData.Protect(plain, DpapiEntropy, DataProtectionScope.CurrentUser);
        byte[] file = new byte[Magic.Length + blob.Length];
        Buffer.BlockCopy(Magic, 0, file, 0, Magic.Length);
        Buffer.BlockCopy(blob, 0, file, Magic.Length, blob.Length);
        return file;
    }

    /// <summary>
    /// Parses a keyfile: v2 envelopes are DPAPI-unwrapped and attestation-
    /// checked; legacy 64-byte raw secrets pass through as
    /// <see cref="AttestState.Missing"/> (self-upgrading on next rotation).
    /// False when the file isn't a keyfile or the envelope can't be
    /// unwrapped (copied to another machine/user, or corrupt).
    /// </summary>
    public static bool TryUnwrapKeyfile(byte[] file, KeyConfig config,
        out byte[]? secret, out AttestState attest, out string detail)
    {
        secret = null;
        attest = AttestState.Missing;

        if (file.Length == SecretLen)
        {
            secret = file;
            detail = "pre-attestation format";
            return true;
        }

        if (file.Length <= Magic.Length
            || !file.AsSpan(0, Magic.Length).SequenceEqual(Magic))
        {
            detail = "not a CryptoKey file";
            return false;
        }

        byte[] plain;
        try
        {
            plain = ProtectedData.Unprotect(file[Magic.Length..], DpapiEntropy,
                DataProtectionScope.CurrentUser);
        }
        catch (CryptographicException)
        {
            detail = "envelope unreadable (foreign machine or corrupt)";
            return false;
        }
        catch (Exception ex)
        {
            detail = $"envelope error: {ex.Message}";
            return false;
        }

        if (plain.Length != SecretLen + AttestLen)
        {
            detail = "envelope malformed";
            return false;
        }

        byte[] unwrapped = plain.AsSpan(0, SecretLen).ToArray();
        ReadOnlySpan<byte> storedAttest = plain.AsSpan(SecretLen, AttestLen);
        bool ok = CryptographicOperations.FixedTimeEquals(storedAttest,
            ConfigStore.ComputeAttest(unwrapped, config));
        attest = ok ? AttestState.Ok : AttestState.Mismatch;
        detail = ok ? "attested" : "config attestation failed — config.json tampered";
        secret = unwrapped;
        return true;
    }

    /// <summary>
    /// Tri-state keyfile check across every mounted letter. A Current match on
    /// any letter wins over Previous matches elsewhere — a stale file on one
    /// partition can't shadow the current one on another. Attestation is
    /// reported from the winning letter.
    /// </summary>
    public static KeyfileCheck Check(KeyConfig config, UsbDisk disk)
    {
        if (disk.DriveLetters.Count == 0)
            return new KeyfileCheck(SecretMatch.None, "device has no mounted volume",
                Array.Empty<string>(), AttestState.Missing);

        var matched = new List<string>();
        bool foundCurrent = false, foundPrevious = false;
        AttestState bestAttest = AttestState.Missing;
        string lastError = "no keyfile found";
        foreach (string letter in disk.DriveLetters)
        {
            string path = KeyFilePath(letter);
            byte[] file;
            try
            {
                file = File.ReadAllBytes(path);
            }
            catch (IOException)
            {
                lastError = $"keyfile missing at {path}";
                continue;
            }
            catch (UnauthorizedAccessException)
            {
                lastError = $"keyfile unreadable at {path}";
                continue;
            }
            catch (Exception ex)
            {
                lastError = $"keyfile read error at {path}: {ex.Message}";
                continue;
            }

            if (!TryUnwrapKeyfile(file, config, out byte[]? secret,
                    out AttestState attest, out string unwrapDetail)
                || secret == null)
            {
                lastError = $"keyfile rejected at {path}: {unwrapDetail}";
                continue;
            }

            switch (ConfigStore.MatchSecret(config, secret))
            {
                case SecretMatch.Current:
                    if (!foundCurrent)
                        bestAttest = attest;
                    foundCurrent = true;
                    matched.Add(letter);
                    break;
                case SecretMatch.Previous:
                    if (!foundCurrent && !foundPrevious)
                        bestAttest = attest;
                    foundPrevious = true;
                    matched.Add(letter);
                    break;
                default:
                    lastError = "keyfile secret mismatch";
                    break;
            }
        }

        if (foundCurrent)
            return new KeyfileCheck(SecretMatch.Current,
                $"verified — generation {config.RotationCount}{AttestSuffix(bestAttest)}",
                matched, bestAttest);
        if (foundPrevious)
            return new KeyfileCheck(SecretMatch.Previous,
                $"stale — previous-generation secret (gen {Math.Max(0, config.RotationCount - 1)})" +
                    AttestSuffix(bestAttest),
                matched, bestAttest);
        return new KeyfileCheck(SecretMatch.None, lastError, matched, AttestState.Missing);
    }

    private static string AttestSuffix(AttestState attest) => attest switch
    {
        AttestState.Missing => " · pre-attestation",
        AttestState.Mismatch => " · ATTESTATION MISMATCH",
        _ => "",
    };

    /// <summary>
    /// Writes a new-generation secret to every letter that already has a
    /// keyfile — v2 envelope, temp file, attributes, atomic move, then a
    /// read-back check. If the keyfile was wiped from every letter, re-arms
    /// the first mounted one so the drive can't stay stale-forever.
    /// </summary>
    public static List<(string Letter, string? Error)> RotateKeyfiles(
        UsbDisk disk, byte[] secret, KeyConfig config)
    {
        byte[] envelope;
        try
        {
            envelope = WrapKeyfile(secret, config);
        }
        catch (Exception ex)
        {
            return new List<(string, string?)> { ("-", $"envelope failed: {ex.Message}") };
        }

        var targets = disk.DriveLetters.Where(l => File.Exists(KeyFilePath(l))).ToList();
        if (targets.Count == 0)
            targets = disk.DriveLetters.Take(1).ToList();

        var results = new List<(string Letter, string? Error)>();
        foreach (string letter in targets)
        {
            string path = KeyFilePath(letter);
            string tmp = path + ".tmp";
            try
            {
                File.WriteAllBytes(tmp, envelope);
                File.SetAttributes(tmp, FileAttributes.Hidden | FileAttributes.System);
                File.Move(tmp, path, overwrite: true);
                byte[] back = File.ReadAllBytes(path);
                bool ok = TryUnwrapKeyfile(back, config, out byte[]? s, out _, out _)
                    && s != null
                    && CryptographicOperations.FixedTimeEquals(s, secret);
                results.Add((letter, ok ? null : "read-back mismatch"));
            }
            catch (Exception ex)
            {
                try { File.Delete(tmp); } catch { }
                results.Add((letter, ex.Message));
            }
        }
        return results;
    }
}
