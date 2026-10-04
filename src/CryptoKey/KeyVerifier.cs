namespace CryptoKey;

/// <summary>Result of checking a mounted device's keyfile against the config.</summary>
internal sealed record KeyfileCheck(
    SecretMatch Match,
    string Detail,
    IReadOnlyList<string> MatchedLetters);

internal static class KeyVerifier
{
    public const string KeyFileName = ".cryptokey";

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
    /// Tri-state keyfile check across every mounted letter. A Current match on
    /// any letter wins over Previous matches elsewhere — a stale file on one
    /// partition can't shadow the current one on another.
    /// </summary>
    public static KeyfileCheck Check(KeyConfig config, UsbDisk disk)
    {
        if (disk.DriveLetters.Count == 0)
            return new KeyfileCheck(SecretMatch.None, "device has no mounted volume", Array.Empty<string>());

        var matched = new List<string>();
        bool foundCurrent = false, foundPrevious = false;
        string lastError = "no keyfile found";
        foreach (string letter in disk.DriveLetters)
        {
            string path = KeyFilePath(letter);
            byte[] secret;
            try
            {
                secret = File.ReadAllBytes(path);
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

            switch (ConfigStore.MatchSecret(config, secret))
            {
                case SecretMatch.Current:
                    foundCurrent = true;
                    matched.Add(letter);
                    break;
                case SecretMatch.Previous:
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
                $"verified — generation {config.RotationCount}", matched);
        if (foundPrevious)
            return new KeyfileCheck(SecretMatch.Previous,
                $"stale — previous-generation secret (gen {Math.Max(0, config.RotationCount - 1)})",
                matched);
        return new KeyfileCheck(SecretMatch.None, lastError, matched);
    }

    /// <summary>
    /// Writes a new-generation secret to every letter that already has a
    /// keyfile — temp file, attributes, atomic move, then a read-back check.
    /// If the keyfile was wiped from every letter, re-arms the first mounted
    /// one so the drive can't stay stale-forever.
    /// </summary>
    public static List<(string Letter, string? Error)> RotateKeyfiles(UsbDisk disk, byte[] secret)
    {
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
                File.WriteAllBytes(tmp, secret);
                File.SetAttributes(tmp, FileAttributes.Hidden | FileAttributes.System);
                File.Move(tmp, path, overwrite: true);
                byte[] back = File.ReadAllBytes(path);
                results.Add((letter,
                    back.AsSpan().SequenceEqual(secret) ? null : "read-back mismatch"));
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
