using Avalonia;
using Avalonia.Controls;

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
            => Guard(devMode, takeover, headless: false);
    }

    private static int Main(string[] args)
    {
        Platform.Init(MacPlatform.Services);

        // Bare `cryptokey` (optionally --dev/--takeover/--headless) = the
        // daemon. Avalonia tier by default; --headless forces the pump path.
        if (args.Length == 0 || args[0].StartsWith("--"))
            return Guard(args.Contains("--dev", StringComparer.OrdinalIgnoreCase),
                args.Contains("--takeover", StringComparer.OrdinalIgnoreCase),
                args.Contains("--headless", StringComparer.OrdinalIgnoreCase));

        // Shared verbs: enroll, status, guard, open, lock, pause, resume,
        // quit, watchdog.
        if (CryptoKeyCli.Run(args, new HostVerbs()) is int shared)
            return shared;

        switch (args[0].ToLowerInvariant())
        {
            case "uitest":
                // Hidden dev smoke: engage the real lock surface (tap +
                // capture + windows) for a few seconds, then release.
                // --dev arms the panic combo; --headless skips the windows.
                return UiTest(args.Contains("--dev", StringComparer.OrdinalIgnoreCase),
                    args.Contains("--headless", StringComparer.OrdinalIgnoreCase));
            case "install":
                return MacInstall.Install();
            case "uninstall":
                return MacInstall.Uninstall();
            case "help":
                Usage();
                return 0;
            default:
                Usage();
                return 1;
        }
    }

    private static int Guard(bool devMode, bool takeover, bool headless)
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

        if (!headless)
        {
            try
            {
                return GuardWithUi(config, devMode);
            }
            catch (Exception ex)
            {
                // UI stack failed — security outranks chrome: run headless.
                Console.WriteLine(
                    $"UI unavailable ({ex.Message}) — running headless.");
            }
        }
        return GuardHeadless(config, devMode);
    }

    /// <summary>Avalonia tier: Dispatcher is the pump, shielding windows + tray.</summary>
    private static int GuardWithUi(KeyConfig config, bool devMode)
    {
        var ui = new AvaloniaUiDispatcher();
        var lockUi = new LockWindowCtl();
        // Deliberate upgrade: Main installed the headless bundle so config
        // failures could alert pre-UI; swap in the UI bundle now.
        Platform.Reinit(MacPlatform.UiServices(ui, lockUi));

        GuardService? service = null;
        IpcServer? ipc = null;
        MacApp.OnStartup = () =>
        {
            MacInterop.HideFromDock(); // daemon — no Dock icon
            service = StartBackend(config, devMode, out ipc);
            MacTray.Install(service);
        };
        try
        {
            AppBuilder.Configure<MacApp>()
                .UsePlatformDetect()
                .WithInterFont()
                .StartWithClassicDesktopLifetime(Array.Empty<string>(),
                    ShutdownMode.OnExplicitShutdown);
            return 0;
        }
        finally
        {
            MacApp.OnStartup = null;
            try { ipc?.Dispose(); } catch (Exception) { }
            try { service?.Dispose(); } catch (Exception) { }
        }
    }

    /// <summary>Headless tier: MacPump main thread, capture+tap lock only.</summary>
    private static int GuardHeadless(KeyConfig config, bool devMode)
    {
        var pump = new MacPump();
        Platform.Reinit(MacPlatform.Headless(pump));
        using var service = StartBackend(config, devMode, out IpcServer? ipc);
        using (ipc)
        {
            pump.Run(); // blocks until AppLifetime.Exit() — quit/panic land here
        }
        return 0;
    }

    private static GuardService StartBackend(
        KeyConfig config, bool devMode, out IpcServer? ipc)
    {
        var service = new GuardService(config, devMode, forceClassic: false);
        ipc = new IpcServer(service.UiDispatcher,
            line => service.DispatchCommand(line));
        service.Start();
        ipc.Start(service.Log);
        return service;
    }

    /// <summary>
    /// Dev-only surface smoke test — engages for 3s like a real lock, then
    /// releases and exits. Proves tap + capture + windows end-to-end without
    /// an enrolled key.
    /// </summary>
    private static int UiTest(bool devMode, bool headless)
    {
        ILockSurface surface;
        if (headless)
        {
            var pump = new MacPump();
            Platform.Reinit(MacPlatform.Headless(pump));
            surface = new MacLockSurface(devMode, null);
            Console.WriteLine("uitest (headless): engaging 3s…");
            bool ok = surface.Engage();
            Console.WriteLine($"  engage={ok} err={surface.EngageError ?? "—"}");
            Thread.Sleep(3000);
            surface.ReleaseInput();
            surface.Dispose();
            Console.WriteLine("released.");
            return ok ? 0 : 1;
        }

        var ui = new AvaloniaUiDispatcher();
        var lockUi = new LockWindowCtl();
        // Deliberate upgrade: Main installed the headless bundle so config
        // failures could alert pre-UI; swap in the UI bundle now.
        Platform.Reinit(MacPlatform.UiServices(ui, lockUi));
        var surfaceBox = new MacLockSurface(devMode, lockUi);
        surface = surfaceBox;
        MacApp.OnStartup = () =>
        {
            MacInterop.HideFromDock();
            // Worker thread — a sleep on the UI thread would freeze the
            // very windows we're testing.
            new Thread(() =>
            {
                Console.WriteLine("uitest: engaging 3s…");
                bool ok = surface.Engage();
                Console.WriteLine($"  engage={ok} err={surface.EngageError ?? "—"}");
                surface.SetStatus("uitest — type to see dots; Enter submits.");
                surface.PassphraseSubmitted += buf =>
                {
                    Console.WriteLine($"  submitted {buf.Length} chars (wiped)");
                    Array.Clear(buf);
                    surface.SetStatus("submitted — releasing…");
                };
                Thread.Sleep(3000);
                if (ok)
                {
                    surface.ReleaseInput();
                    Console.WriteLine("released.");
                }
                surface.Dispose();
                ui.Post(ui.Exit);
            })
            { IsBackground = true }.Start();
        };
        try
        {
            AppBuilder.Configure<MacApp>()
                .UsePlatformDetect()
                .WithInterFont()
                .StartWithClassicDesktopLifetime(Array.Empty<string>(),
                    ShutdownMode.OnExplicitShutdown);
            return 0;
        }
        finally { MacApp.OnStartup = null; }
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
        Console.WriteLine("  cryptokey install       Copy to ~/Applications + LaunchAgent autostart");
        Console.WriteLine("  cryptokey uninstall     Remove the LaunchAgent (binary stays)");
        Console.WriteLine();
        Console.WriteLine("  --dev              enables emergency exit combo Ctrl+Opt+Shift+F12");
        Console.WriteLine("  --headless         run without windows/tray (capture+tap only)");
        Console.WriteLine("  NOTE: the lock needs Accessibility permission (event tap) —");
        Console.WriteLine("        approve the prompt in Privacy & Security → Accessibility.");
    }
}
