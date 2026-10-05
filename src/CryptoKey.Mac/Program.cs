namespace CryptoKey;

/// <summary>
/// macOS host entry point. Phase 2 is headless: `cryptokey`/`guard` run the
/// pump on the main thread with the capture+tap lock surface — no dashboard
/// or tray yet (Phase 3). Shared verbs come from <see cref="CryptoKeyCli"/>.
/// </summary>
internal static class Program
{
    private sealed class HostVerbs : IHostVerbs
    {
        public int RunGuard(bool devMode, bool takeover, bool forceClassic)
            => Guard(devMode, takeover);
    }

    private static int Main(string[] args)
    {
        Platform.Init(MacPlatform.Services);

        // Bare `cryptokey` (optionally --dev) = the daemon. There is no GUI
        // tier yet — same code path as `guard`.
        if (args.Length == 0 || args[0].StartsWith("--"))
            return Guard(args.Contains("--dev", StringComparer.OrdinalIgnoreCase),
                args.Contains("--takeover", StringComparer.OrdinalIgnoreCase));

        // Shared verbs: enroll, status, guard, open, lock, pause, resume,
        // quit, watchdog.
        if (CryptoKeyCli.Run(args, new HostVerbs()) is int shared)
            return shared;

        switch (args[0].ToLowerInvariant())
        {
            case "install":
                Console.WriteLine("install is not wired on macOS yet — run " +
                    "'cryptokey guard' directly (LaunchAgent lands in Phase 4).");
                return 1;
            case "help":
                Usage();
                return 0;
            default:
                Usage();
                return 1;
        }
    }

    private static int Guard(bool devMode, bool takeover)
    {
        if (!CryptoKeyCli.TryLoadConfig(out KeyConfig? config, alertModal: true))
            return 1;
        if (config == null)
        {
            Console.WriteLine("No enrolled key. Run 'cryptokey enroll' first.");
            return 1;
        }

        using IDisposable? singleInstance =
            Platform.Services.SingleInstance.Acquire("CryptoKeyGuard", takeover);
        if (singleInstance == null)
        {
            Console.WriteLine("Another guard instance is already running.");
            return 1;
        }

        if (devMode)
            Console.WriteLine("DEV MODE: panic exit is Ctrl+Opt+Shift+F12.");

        // The pump IS the main thread — GuardService marshals IPC dispatch,
        // idle-lock ticks, and rotation logging through it.
        var pump = (MacPump)Platform.Services.AppLifetime;
        using var service = new GuardService(config, devMode, forceClassic: false);
        using var ipc = new IpcServer(service.UiDispatcher,
            line => service.DispatchCommand(line));
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            Console.WriteLine($"[guard] Fatal background error: {e.ExceptionObject}");

        service.Start();
        ipc.Start(service.Log);
        pump.Run(); // blocks until AppLifetime.Exit() — quit/panic land here
        return 0;
    }

    private static void Usage()
    {
        Console.WriteLine("CryptoKey — USB security key lock (macOS)");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  cryptokey               Run the guard (headless — capture+tap lock)");
        Console.WriteLine("  cryptokey enroll        Register a USB drive as your key");
        Console.WriteLine("  cryptokey status        Show enrollment, key presence, live state");
        Console.WriteLine("  cryptokey lock          Lock now (asks the running guard)");
        Console.WriteLine("  cryptokey pause [mins]  Pause auto-lock (default 5)");
        Console.WriteLine("  cryptokey resume        End a pause early");
        Console.WriteLine("  cryptokey quit          Stop the guard (refused while locked)");
        Console.WriteLine();
        Console.WriteLine("  --dev              enables emergency exit combo Ctrl+Opt+Shift+F12");
        Console.WriteLine("  NOTE: the lock needs Accessibility permission (event tap) —");
        Console.WriteLine("        approve the prompt in Privacy & Security → Accessibility.");
    }
}
