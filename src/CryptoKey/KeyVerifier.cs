namespace CryptoKey;

internal static class KeyVerifier
{
    public const string KeyFileName = ".cryptokey";

    public static string KeyFilePath(string driveLetter)
        => Path.Combine(driveLetter + "\\", KeyFileName);

    /// <summary>
    /// True when the enrolled device is present AND its keyfile secret
    /// verifies against the stored hash.
    /// </summary>
    public static bool Verify(KeyConfig config, out string detail)
    {
        UsbDisk? disk = UsbMonitor.FindDisk(config.DeviceSerial);
        if (disk == null)
        {
            detail = "enrolled device not present";
            return false;
        }

        string? letter = disk.DriveLetters.FirstOrDefault();
        if (letter == null)
        {
            detail = "device has no mounted volume";
            return false;
        }

        string path = KeyFilePath(letter);
        byte[] secret;
        try
        {
            secret = File.ReadAllBytes(path);
        }
        catch (IOException)
        {
            detail = $"keyfile missing at {path}";
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            detail = $"keyfile unreadable at {path}";
            return false;
        }

        bool ok = ConfigStore.VerifySecret(config, secret);
        detail = ok ? "verified" : "keyfile secret mismatch";
        return ok;
    }
}
