using System.Security.Cryptography;
using System.Text;

namespace CryptoKey;

internal static class Enrollment
{
    private const int SecretBytes = 64;

    public static int Run()
    {
        KeyConfig? existing = null;
        try { existing = ConfigStore.Load(); } catch { }
        if (existing != null)
        {
            Console.Write($"A key is already enrolled (serial '{existing.DeviceSerial}'). Overwrite? [y/N] ");
            string? answer = Console.ReadLine()?.Trim();
            if (!string.Equals(answer, "y", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("Enrollment cancelled.");
                return 1;
            }
        }

        List<UsbDisk> disks;
        try
        {
            disks = UsbMonitor.EnumerateUsbDisks();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to enumerate USB disks: {ex.Message}");
            return 1;
        }

        if (disks.Count == 0)
        {
            Console.WriteLine("No USB disks found. Insert a flash drive and try again.");
            return 1;
        }

        Console.WriteLine("USB disks detected:");
        for (int i = 0; i < disks.Count; i++)
        {
            UsbDisk d = disks[i];
            string volumes = d.DriveLetters.Count > 0 ? string.Join(", ", d.DriveLetters) : "(no volume)";
            string serial = string.IsNullOrEmpty(d.SerialNumber) ? "(blank serial)" : d.SerialNumber;
            Console.WriteLine($"  [{i + 1}] {d.Model}  serial={serial}  volumes={volumes}");
        }

        Console.Write("Select drive number: ");
        if (!int.TryParse(Console.ReadLine(), out int pick) || pick < 1 || pick > disks.Count)
        {
            Console.WriteLine("Invalid selection.");
            return 1;
        }

        UsbDisk disk = disks[pick - 1];
        if (string.IsNullOrEmpty(disk.SerialNumber))
            Console.WriteLine("WARNING: this drive reports a blank serial number; matching may be unreliable.");

        string? letter = disk.DriveLetters.FirstOrDefault();
        if (letter == null)
        {
            Console.WriteLine("Selected drive has no mounted volume.");
            return 1;
        }

        string passphrase = ReadMasked("Set failsafe passphrase: ");
        string confirm = ReadMasked("Confirm passphrase: ");
        if (passphrase != confirm)
        {
            Console.WriteLine("Passphrases do not match.");
            return 1;
        }
        if (passphrase.Length < KeyConfig.MinPassphraseLength)
        {
            Console.WriteLine($"Passphrase too short (min {KeyConfig.MinPassphraseLength} characters).");
            return 1;
        }

        // Config first — the v2 keyfile's attestation MAC covers the serial
        // and passphrase hash, so the envelope can't be written until the
        // config fields exist. Keep guard preferences across a re-enroll.
        byte[] secret = RandomNumberGenerator.GetBytes(SecretBytes);
        KeyConfig fresh = ConfigStore.CreateNew(disk.SerialNumber, secret, passphrase);
        if (existing?.Guard != null)
            fresh.Guard = existing.Guard;

        string keyPath = KeyVerifier.KeyFilePath(letter);
        string tmpPath = keyPath + ".tmp";
        try
        {
            // v2 envelope: DPAPI-bound to this user/machine + attestation MAC.
            File.WriteAllBytes(tmpPath, KeyVerifier.WrapKeyfile(secret, fresh));
            File.SetAttributes(tmpPath, FileAttributes.Hidden | FileAttributes.System);
            File.Move(tmpPath, keyPath, overwrite: true);
        }
        catch (Exception ex)
        {
            try { File.Delete(tmpPath); } catch { }
            Console.WriteLine($"Failed to write keyfile to {keyPath}: {ex.Message}");
            return 1;
        }

        try
        {
            ConfigStore.Save(fresh);
        }
        catch (Exception ex)
        {
            // Don't leave a keyfile on the drive that verifies against nothing.
            try { File.Delete(keyPath); } catch { }
            Console.WriteLine($"Failed to save config to {ConfigStore.ConfigPath}: {ex.Message}");
            return 1;
        }

        Console.WriteLine($"Enrolled {disk.Model} on {letter}. Keyfile written to {keyPath}");
        Console.WriteLine($"Config saved to {ConfigStore.ConfigPath}");
        return 0;
    }

    private static string ReadMasked(string prompt)
    {
        Console.Write(prompt);
        if (Console.IsInputRedirected)
        {
            string? line = Console.ReadLine();
            Console.WriteLine();
            return line ?? "";
        }
        var sb = new StringBuilder();
        while (true)
        {
            ConsoleKeyInfo key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                return sb.ToString();
            }
            if (key.Key == ConsoleKey.Backspace)
            {
                if (sb.Length > 0)
                {
                    sb.Length--;
                    Console.Write("\b \b");
                }
            }
            else if (!char.IsControl(key.KeyChar))
            {
                sb.Append(key.KeyChar);
                Console.Write('*');
            }
        }
    }
}
