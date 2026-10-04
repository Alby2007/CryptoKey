namespace CryptoKey;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            Usage();
            return 1;
        }

        switch (args[0].ToLowerInvariant())
        {
            case "enroll":
                return Enrollment.Run();
            case "status":
                return Status();
            case "guard":
                return Guard(args.Contains("--dev", StringComparer.OrdinalIgnoreCase));
            default:
                Usage();
                return 1;
        }
    }

    private static int Guard(bool devMode)
    {
        KeyConfig? config = ConfigStore.Load();
        if (config == null)
        {
            Console.WriteLine("No enrolled key. Run 'cryptokey enroll' first.");
            return 1;
        }
        if (devMode)
            Console.WriteLine("DEV MODE: panic exit is Ctrl+Alt+Shift+F12.");

        ApplicationConfiguration.Initialize();
        using var service = new GuardService(config, devMode);
        service.Start();
        Application.Run();
        return 0;
    }

    private static int Status()
    {
        KeyConfig? config = ConfigStore.Load();
        if (config == null)
        {
            Console.WriteLine($"Not enrolled (no config at {ConfigStore.ConfigPath}).");
            return 1;
        }

        Console.WriteLine($"Config:        {ConfigStore.ConfigPath}");
        Console.WriteLine($"Device serial: {config.DeviceSerial}");

        UsbDisk? disk = UsbMonitor.FindDisk(config.DeviceSerial);
        if (disk == null)
        {
            Console.WriteLine("Key:           ABSENT");
            return 0;
        }

        string volumes = disk.DriveLetters.Count > 0 ? string.Join(", ", disk.DriveLetters) : "(no volume)";
        Console.WriteLine($"Key:           PRESENT — {disk.Model} on {volumes}");
        Console.WriteLine(KeyVerifier.Verify(config, out string detail)
            ? "Keyfile:       verified"
            : $"Keyfile:       FAILED ({detail})");
        return 0;
    }

    private static void Usage()
    {
        Console.WriteLine("CryptoKey — USB security key PC lock");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  cryptokey enroll        Register a USB drive as your key");
        Console.WriteLine("  cryptokey guard [--dev] Lock the PC while the key is absent");
        Console.WriteLine("  cryptokey status        Show current enrollment and key presence");
        Console.WriteLine();
        Console.WriteLine("  --dev  enables emergency exit combo Ctrl+Alt+Shift+F12");
    }
}
