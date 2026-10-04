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
            case "lock":
                return SendIpc("lock");
            case "pause":
                int mins = args.Length > 1 && int.TryParse(args[1], out int m) ? m : 5;
                return SendIpc($"pause {mins}");
            case "resume":
                return SendIpc("resume");
            default:
                Usage();
                return 1;
        }
    }

    private static int SendIpc(string command)
    {
        string? reply = IpcClient.Send(command);
        if (reply == null)
        {
            Console.WriteLine("cryptokey guard is not running.");
            return 1;
        }
        Console.WriteLine(reply);
        return reply.StartsWith("ok", StringComparison.Ordinal) ? 0 : 1;
    }

    private static int Guard(bool devMode)
    {
        if (!TryLoadConfig(out KeyConfig? config))
            return 1;
        if (config == null)
        {
            Console.WriteLine("No enrolled key. Run 'cryptokey enroll' first.");
            return 1;
        }

        using var singleInstance = new Mutex(true, @"Local\CryptoKeyGuard", out bool createdNew);
        if (!createdNew)
        {
            Console.WriteLine("Another guard instance is already running.");
            return 1;
        }

        if (devMode)
            Console.WriteLine("DEV MODE: panic exit is Ctrl+Alt+Shift+F12.");

        ApplicationConfiguration.Initialize();

        using var service = new GuardService(config, devMode);
        using var tray = new TrayApp(service, config);
        using var ipc = new IpcServer(service.InvokeTarget, service.DispatchCommand);
        // A UI-thread exception while locked can leave input swallowed behind
        // a dead overlay — an invisible soft-brick. Fail dead instead: free
        // the input, then kill the process (hooks die with it anyway).
        Application.ThreadException += (_, e) =>
        {
            Console.WriteLine($"[guard] Fatal UI error: {e.Exception.Message}");
            try { service.ReleaseInput(); } catch { }
            Environment.Exit(2);
        };
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            Console.WriteLine($"[guard] Fatal background error: {((Exception)e.ExceptionObject).Message}");

        service.Start();
        ipc.Start();
        Application.Run();
        return 0;
    }

    private static bool TryLoadConfig(out KeyConfig? config)
    {
        try
        {
            config = ConfigStore.Load();
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Config at {ConfigStore.ConfigPath} is corrupt: {ex.Message}");
            config = null;
            return false;
        }
    }

    private static int Status()
    {
        if (!TryLoadConfig(out KeyConfig? config))
            return 1;
        if (config == null)
        {
            Console.WriteLine($"Not enrolled (no config at {ConfigStore.ConfigPath}).");
            return 1;
        }

        Console.WriteLine($"Config:        {ConfigStore.ConfigPath}");
        Console.WriteLine($"Device serial: {config.DeviceSerial}");

        int exitCode;
        UsbDisk? disk;
        try
        {
            disk = UsbMonitor.FindDisk(config.DeviceSerial);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Key:           UNKNOWN (enumeration failed: {ex.Message})");
            PrintLiveGuard();
            return 1;
        }
        if (disk == null)
        {
            Console.WriteLine("Key:           ABSENT");
            exitCode = 1;
        }
        else
        {
            string volumes = disk.DriveLetters.Count > 0 ? string.Join(", ", disk.DriveLetters) : "(no volume)";
            Console.WriteLine($"Key:           PRESENT — {disk.Model} on {volumes}");
            bool ok = KeyVerifier.Verify(config, disk, out string detail);
            Console.WriteLine(ok ? "Keyfile:       verified" : $"Keyfile:       FAILED ({detail})");
            exitCode = ok ? 0 : 1;
        }

        PrintLiveGuard();
        return exitCode;
    }

    private static void PrintLiveGuard()
    {
        string? live = IpcClient.Send("status", 800);
        Console.WriteLine(live != null
            ? $"Guard:         {live}"
            : "Guard:         not running");
    }

    private static void Usage()
    {
        Console.WriteLine("CryptoKey — USB security key PC lock");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  cryptokey enroll        Register a USB drive as your key");
        Console.WriteLine("  cryptokey guard [--dev] Lock the PC while the key is absent (tray icon)");
        Console.WriteLine("  cryptokey status        Show current enrollment, key presence, live state");
        Console.WriteLine("  cryptokey lock          Lock now (asks the running guard)");
        Console.WriteLine("  cryptokey pause [mins]  Pause auto-lock (default 5)");
        Console.WriteLine("  cryptokey resume        End a pause early");
        Console.WriteLine();
        Console.WriteLine("  --dev  enables emergency exit combo Ctrl+Alt+Shift+F12");
    }
}
