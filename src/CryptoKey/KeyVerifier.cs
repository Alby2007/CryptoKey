namespace CryptoKey;

internal static class KeyVerifier
{
    public const string KeyFileName = ".cryptokey";

    public static string KeyFilePath(string driveLetter)
        => Path.Combine(driveLetter + "\\", KeyFileName);

    /// <summary>
    /// True when the enrolled device is present AND its keyfile secret
    /// verifies against the stored hash. Never throws — failures mean "not
    /// verified", so callers can safely fail closed.
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
        if (disk.DriveLetters.Count == 0)
        {
            detail = "device has no mounted volume";
            return false;
        }

        // Multi-partition drives: try every mounted letter, not just the first.
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

            if (ConfigStore.VerifySecret(config, secret))
            {
                detail = "verified";
                return true;
            }
            lastError = "keyfile secret mismatch";
        }
        detail = lastError;
        return false;
    }
}
