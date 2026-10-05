using System.Security.Cryptography;

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

        // The recovery phrase is generated, not chosen — shown once, stored
        // only as a hash, and confirmed by retyping.
        string phrase = RecoveryPhrase.Generate();
        Console.WriteLine();
        Console.WriteLine("Your recovery phrase — the failsafe when the key isn't available:");
        Console.WriteLine();
        Console.WriteLine($"    {phrase}");
        Console.WriteLine();
        Console.WriteLine("Write it down somewhere safe — it is shown ONCE and stored only as a hash.");
        if (!ConfirmPhrase(phrase))
            return 1;

        // Config first — the v2 keyfile's attestation MAC covers the serial
        // and phrase hash, so the envelope can't be written until the
        // config fields exist. Keep guard preferences across a re-enroll.
        byte[] secret = RandomNumberGenerator.GetBytes(SecretBytes);
        KeyConfig fresh = ConfigStore.CreateNew(disk.SerialNumber, secret, phrase);
        if (existing?.Guard != null)
            fresh.Guard = existing.Guard;

        string keyPath = KeyVerifier.KeyFilePath(letter);
        try
        {
            // v2 envelope: DPAPI-bound to this user/machine + attestation MAC.
            // AtomicFile flushes to media before the rename — no truncated
            // keyfile if the drive is pulled mid-write.
            AtomicFile.WriteAllBytes(keyPath, KeyVerifier.WrapKeyfile(secret, fresh));
            File.SetAttributes(keyPath, FileAttributes.Hidden | FileAttributes.System);
        }
        catch (Exception ex)
        {
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

        // A fresh enroll is when the app becomes real — drop the shell
        // shortcuts now (also repoints them if the exe moved). Best-effort:
        // a shortcut failure must never fail enrollment.
        try
        {
            ShortcutManager.SetEnabled(ShortcutTarget.StartMenu, true);
            ShortcutManager.SetEnabled(ShortcutTarget.Desktop, true);
            Console.WriteLine("Shortcuts created: Start Menu + Desktop.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Shortcut creation skipped: {ex.Message}");
        }

        Console.WriteLine($"Enrolled {disk.Model} on {letter}. Keyfile written to {keyPath}");
        Console.WriteLine($"Config saved to {ConfigStore.ConfigPath}");
        return 0;
    }

    /// <summary>
    /// Retype-to-confirm for the generated phrase. Plain echo is fine — the
    /// phrase is already on screen. Normalization makes case, separators,
    /// and ambiguous glyphs (O/0, I/L/1) forgiveable; up to 3 tries.
    /// </summary>
    private static bool ConfirmPhrase(string phrase)
    {
        Span<char> wantBuf = stackalloc char[64];
        Span<char> gotBuf = stackalloc char[64];
        try
        {
            int wantLen = RecoveryPhrase.Normalize(phrase.AsSpan(), wantBuf);
            for (int tries = 1; tries <= 3; tries++)
            {
                Console.Write("Retype the phrase to confirm: ");
                string? typed = Console.ReadLine();
                int gotLen = RecoveryPhrase.Normalize(typed.AsSpan(), gotBuf);
                if (gotLen == wantLen
                    && gotBuf[..gotLen].SequenceEqual(wantBuf[..wantLen]))
                    return true;
                Console.WriteLine(tries < 3
                    ? "That doesn't match — check each group and try again."
                    : "Confirmation failed — enrollment aborted.");
            }
            return false;
        }
        finally
        {
            wantBuf.Clear();
            gotBuf.Clear();
        }
    }
}
