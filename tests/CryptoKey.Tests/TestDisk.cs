using System.Security.Cryptography;

namespace CryptoKey.Tests;

/// <summary>
/// Test seam: UsbDisk is a record — a temp directory stands in for a drive
/// letter (KeyFilePath joins letter + "\\" + ".cryptokey", so a full path
/// works). No fakes, no interfaces, no production changes.
/// </summary>
internal static class TestDisk
{
    public static UsbDisk For(params string[] letters)
        => new("TEST\\DISK", "TEST-SERIAL", "Test Disk", letters.ToList());

    public static string TempDir()
    {
        string dir = Path.Combine(Path.GetTempPath(), "cktest-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    /// <summary>Writes a v2-envelope keyfile carrying <paramref name="secret"/>.</summary>
    public static void WriteKeyfile(string letter, byte[] secret, KeyConfig config)
        => File.WriteAllBytes(KeyVerifier.KeyFilePath(letter),
            KeyVerifier.WrapKeyfile(secret, config));

    public static byte[] RandomSecret() => RandomNumberGenerator.GetBytes(64);

    public static KeyConfig NewConfig(byte[] secret, string passphrase = "passphrase-ok")
        => ConfigStore.CreateNew("TEST-SERIAL", secret, passphrase);
}
