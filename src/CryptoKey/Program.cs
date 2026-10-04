namespace CryptoKey;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        // Elevated helper: the parent app spawns this with runas when a
        // startup-mode change needs admin rights (scheduled-task writes).
        if (args.Length >= 1 && args[0].Equals("--set-startup", StringComparison.OrdinalIgnoreCase))
        {
            // IsDefined rejects numeric junk ("--set-startup 99") that TryParse
            // would happily produce and SetMode would treat as Off.
            if (args.Length >= 2
                && Enum.TryParse<StartupMode>(args[1], true, out StartupMode sm)
                && Enum.IsDefined(sm))
                return SetStartupMode(sm);
            Console.WriteLine("usage: cryptokey --set-startup off|normal|elevated");
            return 1;
        }

        // Bare `cryptokey` (optionally `--dev`) = desktop app: guard + dashboard.
        if (args.Length == 0 || args[0].StartsWith("--"))
            return Gui(args.Contains("--dev", StringComparer.OrdinalIgnoreCase),
                args.Contains("--takeover", StringComparer.OrdinalIgnoreCase));

        switch (args[0].ToLowerInvariant())
        {
            case "enroll":
                int erc = Enrollment.Run();
                if (erc == 0)
                    // A running guard holds the old config in memory — ping it
                    // so it reloads and watches the new key's serial.
                    _ = IpcClient.Send("reenrolled", 400);
                return erc;
            case "status":
                return Status();
            case "guard":
                return Guard(args.Contains("--dev", StringComparer.OrdinalIgnoreCase),
                    args.Contains("--takeover", StringComparer.OrdinalIgnoreCase));
            case "open":
                return SendIpc("open");
            case "lock":
                return SendIpc("lock");
            case "pause":
                int mins = args.Length > 1 && int.TryParse(args[1], out int m) ? m : 5;
                return SendIpc($"pause {mins}");
            case "resume":
                return SendIpc("resume");
            case "quit":
                return SendIpc("quit");
            case "help":
                Usage();
                return 0;
            default:
                Usage();
                return 1;
        }
    }

    private static int Gui(bool devMode, bool takeover)
    {
        if (!TryLoadConfig(out KeyConfig? config))
            return 1;
        if (config == null)
        {
            Console.WriteLine("No enrolled key — starting enroll first.");
            if (Enrollment.Run() != 0
                || !TryLoadConfig(out config)
                || config == null)
                return 1;
        }

        using Mutex singleInstance = AcquireGuardMutex(takeover, out bool createdNew);
        if (!createdNew)
        {
            // Guard already up — just raise its window.
            return SendIpc("open");
        }

        return RunApp(config, devMode, openDashboard: true);
    }

    private static string OpenWindow(AppShell shell)
    {
        shell.OpenWindow();
        return "ok opened";
    }

    // A double-clicked console app owns its console; hiding it makes the exe
    // feel like a normal windowed app. A console shared with a shell stays.
    private static void HideConsoleIfOwned()
    {
        try
        {
            var ids = new uint[2];
            uint count = NativeMethods.GetConsoleProcessList(ids, (uint)ids.Length);
            if (count <= 1)
                NativeMethods.ShowWindow(NativeMethods.GetConsoleWindow(), NativeMethods.SW_HIDE);
        }
        catch (Exception)
        {
            // Not a console host (or enumeration failed) — nothing to hide.
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

    private static int Guard(bool devMode, bool takeover)
    {
        if (!TryLoadConfig(out KeyConfig? config))
            return 1;
        if (config == null)
        {
            Console.WriteLine("No enrolled key. Run 'cryptokey enroll' first.");
            return 1;
        }

        using Mutex singleInstance = AcquireGuardMutex(takeover, out bool createdNew);
        if (!createdNew)
        {
            Console.WriteLine("Another guard instance is already running.");
            return 1;
        }

        if (devMode)
            Console.WriteLine("DEV MODE: panic exit is Ctrl+Alt+Shift+F12.");

        return RunApp(config, devMode, openDashboard: false);
    }

    // Shared body for the desktop app and the tray-only daemon: the only
    // difference is whether the dashboard opens on launch. Hiding the console
    // matters most here — both autostart modes invoke `guard`, and without
    // this a console window pops up at every login.
    private static int RunApp(KeyConfig config, bool devMode, bool openDashboard)
    {
        HideConsoleIfOwned();
        ApplicationConfiguration.Initialize();
        Application.SetColorMode(SystemColorMode.Dark);
        Animator.Enabled = config.Guard.Animations;

        using var service = new GuardService(config, devMode);
        using var shell = new AppShell(service, config, devMode);
        using var ipc = new IpcServer(service.InvokeTarget,
            line => line.Trim().Equals("open", StringComparison.OrdinalIgnoreCase)
                ? OpenWindow(shell)
                : service.DispatchCommand(line));
        // A UI-thread exception while locked can leave input swallowed behind
        // a dead overlay — an invisible soft-brick. Fail dead instead: free
        // the input, then kill the process (hooks die with it anyway).
        Application.ThreadException += (_, e) =>
        {
            Console.WriteLine($"[guard] Fatal UI error: {e.Exception}");
            try { service.ReleaseInput(); } catch { }
            Environment.Exit(2);
        };
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            Console.WriteLine($"[guard] Fatal background error: {e.ExceptionObject}");

        service.Start();
        ipc.Start();
        if (openDashboard)
            shell.OpenWindow();
        Application.Run();
        return 0;
    }

    private static int SetStartupMode(StartupMode mode)
    {
        // runas gives this console-app helper a console nobody reads — hide it.
        HideConsoleIfOwned();
        try
        {
            StartupManager.SetMode(mode);
            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message); // exit code is the real channel
            return 1;
        }
    }

    /// <summary>
    /// Claims the single-guard mutex. With <paramref name="waitForRelease"/>,
    /// retries for ~30s so a relaunch (e.g. elevated) can take over the moment
    /// the old instance exits — no unguarded gap between the two.
    /// </summary>
    private static Mutex AcquireGuardMutex(bool waitForRelease, out bool createdNew)
    {
        var deadline = DateTime.UtcNow.AddSeconds(30);
        Mutex m;
        do
        {
            m = new Mutex(true, @"Local\CryptoKeyGuard", out createdNew);
            if (createdNew)
                return m;
            m.Dispose();
            if (waitForRelease)
                Thread.Sleep(250);
        }
        while (waitForRelease && DateTime.UtcNow < deadline);
        return m;
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
        Console.WriteLine("  cryptokey [--dev]       Launch the app (dashboard + tray + guard)");
        Console.WriteLine("  cryptokey enroll        Register a USB drive as your key");
        Console.WriteLine("  cryptokey guard [--dev] Lock the PC while the key is absent (tray only)");
        Console.WriteLine("  cryptokey open          Raise the dashboard of a running guard");
        Console.WriteLine("  cryptokey status        Show current enrollment, key presence, live state");
        Console.WriteLine("  cryptokey lock          Lock now (asks the running guard)");
        Console.WriteLine("  cryptokey pause [mins]  Pause auto-lock (default 5)");
        Console.WriteLine("  cryptokey resume        End a pause early");
        Console.WriteLine("  cryptokey quit          Stop the guard (refused while locked)");
        Console.WriteLine();
        Console.WriteLine("  --dev  enables emergency exit combo Ctrl+Alt+Shift+F12");
    }
}
