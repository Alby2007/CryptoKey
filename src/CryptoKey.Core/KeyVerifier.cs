using System.Security.Cryptography;
using System.Text;

namespace CryptoKey;

/// <summary>
/// Result of checking a mounted device's keyfile against the config.
/// <paramref name="Secret"/> is the winning device secret on a match —
/// ownership transfers to the consumer (VaultService copies it into a
/// pinned buffer and zeroes this array); null on failure. Never serialized,
/// never logged.
/// </summary>
internal sealed record KeyfileCheck(
    SecretMatch Match,
    string Detail,
    IReadOnlyList<string> MatchedLetters,
    AttestState Attest,
    byte[]? Secret = null);

internal static class KeyVerifier
{
    public const string KeyFileName = ".cryptokey";

    /// <summary>v2 envelope: magic || ProtectedData(secret[64] || attest[32]).</summary>
    private static readonly byte[] Magic = "CKY2"u8.ToArray();
    /// <summary>Protection-scope tag — DPAPI entropy on Windows, keychain
    /// item discriminator on macOS. Same value everywhere; each
    /// <see cref="IKeyProtector"/> maps it onto its own store.</summary>
    internal static readonly byte[] ProtectorEntropy = Encoding.UTF8.GetBytes("CryptoKey.v2");
    private const int SecretLen = 64;
    private const int AttestLen = 32;

    /// <param name="volumePath">A mount point — "E:" on Windows,
    /// "/Volumes/NAME" on macOS (trailing separator normalized).</param>
    public static string KeyFilePath(string volumePath)
        => Path.Combine(
            volumePath.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar,
            KeyFileName);

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
            disk = Platform.Services.Usb.FindDisk(config.DeviceSerial);
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
    /// Wraps a secret into the v2 keyfile envelope: bound to this
    /// user+machine by the platform protector, carrying the config
    /// attestation MAC inside the protected blob so a copied file is dead
    /// weight off this machine.
    /// </summary>
    public static byte[] WrapKeyfile(byte[] secret, KeyConfig config)
    {
        byte[] plain = new byte[SecretLen + AttestLen];
        try
        {
            Buffer.BlockCopy(secret, 0, plain, 0, SecretLen);
            Buffer.BlockCopy(ConfigStore.ComputeAttest(secret, config), 0, plain, SecretLen, AttestLen);
            byte[] blob = Platform.Services.Protector.Protect(plain, ProtectorEntropy);
            byte[] file = new byte[Magic.Length + blob.Length];
            Buffer.BlockCopy(Magic, 0, file, 0, Magic.Length);
            Buffer.BlockCopy(blob, 0, file, Magic.Length, blob.Length);
            return file;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain); // raw secret+attest — not ours to keep
        }
    }

    /// <summary>
    /// Parses a keyfile: v2 envelopes are unwrapped by the platform
    /// protector and attestation-checked; legacy 64-byte raw secrets pass
    /// through as <see cref="AttestState.Missing"/> (self-upgrading on next
    /// rotation).
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
            plain = Platform.Services.Protector.Unprotect(
                file[Magic.Length..], ProtectorEntropy);
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
        bool ok = ConfigStore.AttestMatches(unwrapped, config, storedAttest);
        CryptographicOperations.ZeroMemory(plain); // secret+attest blob — done with it
        attest = ok ? AttestState.Ok : AttestState.Mismatch;
        detail = ok ? "attested" : "config attestation failed — config.json tampered";
        secret = unwrapped;
        return true;
    }

    /// <summary>
    /// Tri-state keyfile check across every mounted volume. A Current match
    /// on any volume wins over Previous matches elsewhere — a stale file on
    /// one partition can't shadow the current one on another. Attestation
    /// is reported from the winning volume.
    /// </summary>
    public static KeyfileCheck Check(KeyConfig config, UsbDisk disk)
    {
        if (disk.VolumePaths.Count == 0)
            return new KeyfileCheck(SecretMatch.None, "device has no mounted volume",
                Array.Empty<string>(), AttestState.Missing);

        var matched = new List<string>();
        bool foundCurrent = false, foundPrevious = false;
        AttestState bestAttest = AttestState.Missing;
        byte[]? winningSecret = null;
        string lastError = "no keyfile found";
        foreach (string volume in disk.VolumePaths)
        {
            string path = KeyFilePath(volume);
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
                    {
                        bestAttest = attest;
                        if (winningSecret != null)
                            CryptographicOperations.ZeroMemory(winningSecret); // displaced stale winner
                        winningSecret = secret;
                    }
                    else
                    {
                        CryptographicOperations.ZeroMemory(secret); // losing copy
                    }
                    foundCurrent = true;
                    matched.Add(volume);
                    break;
                case SecretMatch.Previous:
                    if (!foundCurrent && !foundPrevious)
                    {
                        bestAttest = attest;
                        winningSecret = secret;
                    }
                    else
                    {
                        CryptographicOperations.ZeroMemory(secret); // losing copy
                    }
                    foundPrevious = true;
                    matched.Add(volume);
                    break;
                default:
                    CryptographicOperations.ZeroMemory(secret); // not the secret — drop it
                    lastError = "keyfile secret mismatch";
                    break;
            }
        }

        if (foundCurrent)
            return new KeyfileCheck(SecretMatch.Current,
                $"verified — generation {config.RotationCount}{AttestSuffix(bestAttest)}",
                matched, bestAttest, winningSecret);
        if (foundPrevious)
            return new KeyfileCheck(SecretMatch.Previous,
                $"stale — previous-generation secret (gen {Math.Max(0, config.RotationCount - 1)})" +
                    AttestSuffix(bestAttest),
                matched, bestAttest, winningSecret);
        return new KeyfileCheck(SecretMatch.None, lastError, matched, AttestState.Missing);
    }

    private static string AttestSuffix(AttestState attest) => attest switch
    {
        AttestState.Missing => " · pre-attestation",
        AttestState.Mismatch => " · ATTESTATION MISMATCH",
        _ => "",
    };

    /// <summary>
    /// Writes a pre-wrapped v2 envelope to every volume that already has a
    /// keyfile — temp file, attributes, atomic move, then a byte-for-byte
    /// read-back check. If the keyfile was wiped from every volume, re-arms
    /// the first mounted one so the drive can't stay stale-forever. Pure
    /// file I/O — safe off the UI thread; nothing reads mutable config.
    /// </summary>
    public static List<(string Volume, string? Error)> RotateKeyfiles(
        UsbDisk disk, byte[] envelope)
    {
        var targets = disk.VolumePaths.Where(v => File.Exists(KeyFilePath(v))).ToList();
        if (targets.Count == 0)
            targets = disk.VolumePaths.Take(1).ToList();

        var results = new List<(string Volume, string? Error)>();
        foreach (string volume in targets)
        {
            string path = KeyFilePath(volume);
            try
            {
                // Flushed to media before the rename — USB is usually FAT32/
                // exFAT (no journal), so a mid-write yank must never leave a
                // truncated keyfile at the final name.
                AtomicFile.WriteAllBytes(path, envelope);
                Platform.Services.KeyfileAttrs.Hide(path);
                byte[] back = File.ReadAllBytes(path);
                results.Add((volume,
                    back.AsSpan().SequenceEqual(envelope) ? null : "read-back mismatch"));
            }
            catch (Exception ex)
            {
                results.Add((volume, ex.Message));
            }
        }
        return results;
    }
}
