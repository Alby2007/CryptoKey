using Avalonia;
using Avalonia.Controls;
using Avalonia.Threading;
using CryptoKey.Ui;

namespace CryptoKey;

/// <summary>
/// macOS host entry point. Bare `cryptokey` is the desktop app — dashboard,
/// menu-bar tray and guard in one Avalonia process; `cryptokey guard` is
/// the tray-only daemon and `--headless` forces the windowless pump.
/// Shared verbs come from <see cref="CryptoKeyCli"/>.
/// </summary>
internal static class Program
{
    private sealed class HostVerbs : IHostVerbs
    {
        public int RunGuard(bool devMode, bool takeover, bool forceClassic)
            => Guard(devMode, takeover, headless: false, openDashboard: false);
    }

    private static int Main(string[] args)
    {
        Platform.Init(MacPlatform.Services);

        // cryptokey:// deep link — forward to a live guard, else the GUI
        // carries it as its launch link (reset face on the auth window).
        if (args.Length > 0
            && args[0].StartsWith("cryptokey://", StringComparison.OrdinalIgnoreCase))
        {
            string url = args[0];
            if (IpcClient.Send("deeplink " + url, 600) != null)
                return 0;
            return Guard(args.Contains("--dev", StringComparer.OrdinalIgnoreCase),
                args.Contains("--takeover", StringComparer.OrdinalIgnoreCase),
                headless: false, openDashboard: true, deepLink: url);
        }

        // Bare `cryptokey` (optionally --dev/--takeover/--headless) = the
        // desktop app. Avalonia tier by default; --headless forces the pump.
        if (args.Length == 0 || args[0].StartsWith("--"))
            return Guard(args.Contains("--dev", StringComparer.OrdinalIgnoreCase),
                args.Contains("--takeover", StringComparer.OrdinalIgnoreCase),
                args.Contains("--headless", StringComparer.OrdinalIgnoreCase),
                openDashboard: true);

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

    private static int Guard(bool devMode, bool takeover, bool headless,
        bool openDashboard, string? deepLink = null)
    {
        if (!CryptoKeyCli.TryLoadConfig(out KeyConfig? config, alertModal: true))
            return 1;
        if (config == null && !openDashboard)
        {
            Console.WriteLine("No enrolled key. Run 'cryptokey enroll' first.");
            return 1;
        }

        using IDisposable? singleInstance =
            Platform.Services.SingleInstance.Acquire("CryptoKeyGuard", takeover);
        if (singleInstance == null)
        {
            // Guard already up — route a deep link through, else raise it.
            if (deepLink != null)
                return CryptoKeyCli.SendIpc("deeplink " + deepLink);
            Console.WriteLine("Another guard instance is already running.");
            return 1;
        }

        if (devMode)
            Console.WriteLine("DEV MODE: panic exit is Ctrl+Opt+Shift+F12.");

        if (config == null && headless)
        {
            // The headless pump can't run the onboarding wizard — the
            // console enroll verb is the no-UI path.
            Console.WriteLine("No enrolled key — run 'cryptokey enroll', or " +
                "launch 'cryptokey' without --headless for the wizard.");
            return 1;
        }

        if (!headless)
        {
            try
            {
                // config == null lands here only on the desktop path — the
                // wizard enrolls before the guard starts.
                return GuardWithUi(config, devMode, openDashboard, deepLink);
            }
            catch (Exception ex)
            {
                // UI stack failed — security outranks chrome: run headless.
                // With no config that still means enroll on the console.
                if (config == null)
                {
                    Console.WriteLine(
                        $"UI unavailable ({ex.Message}) — run 'cryptokey enroll'.");
                    return 1;
                }
                Console.WriteLine(
                    $"UI unavailable ({ex.Message}) — running headless.");
            }
        }
        return GuardHeadless(config!, devMode);
    }

    /// <summary>
    /// Avalonia tier: the shared app (CryptoKeyApp) on the main thread —
    /// dashboard, menu-bar tray, notifications — with the guard engine in
    /// the same process (engine events are already on this thread).
    /// </summary>
    private static int GuardWithUi(KeyConfig? config, bool devMode,
        bool openDashboard, string? deepLink)
    {
        var ui = new AvaloniaUiDispatcher();
        var lockUi = new LockWindowCtl();
        // Deliberate upgrade: Main installed the headless bundle so config
        // failures could alert pre-UI; swap in the UI bundle now.
        Platform.Reinit(MacPlatform.UiServices(ui, lockUi));

        GuardService? service = null;
        IpcServer? ipc = null;
        UiShell? shell = null;
        int exitCode = 0;
        var host = new MacUiHost();

        void StartGuard(KeyConfig cfg)
        {
            service = new GuardService(cfg, devMode, forceClassic: false);
            ipc = new IpcServer(service.UiDispatcher, line =>
            {
                // 'open' is a UI verb — the dashboard is this process, so
                // route it straight to the shell instead of the engine.
                string[] parts = line.Trim().Split(' ', 2,
                    StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length > 0
                    && parts[0].Equals("open", StringComparison.OrdinalIgnoreCase))
                {
                    Route route = Routes.Parse(parts.Length > 1 ? parts[1] : null);
                    UiRuntime.Post(() => shell?.OpenWindow(route));
                    return "ok opened";
                }
                if (parts.Length > 1
                    && parts[0].Equals("deeplink", StringComparison.OrdinalIgnoreCase))
                {
                    if (shell == null)
                        return "err no dashboard";
                    UiRuntime.Post(() => shell?.OnDeepLink(parts[1]));
                    return "ok";
                }
                return service.DispatchCommand(line);
            });
            service.Start();
            ipc.Start(service.Log);

            var client = new GuardClient(service, cfg, devMode, UiRuntime.Post);
            shell = new UiShell(client, host);
            UiRuntime.InstallCrashPolicy(client.Log, () => shell?.CloseWindows());
            if (deepLink != null)
                UiRuntime.Post(() => shell?.OnDeepLink(deepLink));
            if (openDashboard)
                shell.OpenWindow();
        }

        UiRuntime.Run(b => b.UsePlatformDetect(), _ =>
        {
            // Daemon by default — the Dock icon appears only while a real
            // window is up (dashboard or the first-run wizard).
            MacInterop.HideFromDock();

            // Bind the enrolled account record (or the pending pre-enroll
            // one) before any auth-gated surface asks.
            AuthService.Current.BindConfig(config);

            if (config != null)
            {
                // Guard first — protection never waits for sign-in; the
                // account gate rides on OpenWindow.
                StartGuard(config);
                return;
            }

            // First run: the wizard enrolls a key before the guard starts —
            // Dock icon up while a real window is showing.
            MacInterop.SetDockVisible(true);

            void ShowWizard()
            {
                var wizard = new OnboardingWindow(host, firstRun: true,
                    (flow, configure) => Task.Run(() => flow.Commit(configure)));
                wizard.Closed += (_, _) =>
                {
                    if (wizard.Enrolled
                        && CryptoKeyCli.TryLoadConfig(out KeyConfig? fresh, alertModal: true)
                        && fresh != null)
                    {
                        StartGuard(fresh);
                    }
                    else
                    {
                        exitCode = 1;
                        UiRuntime.Shutdown();
                    }
                };
                wizard.Show();
            }

            // The account gate precedes the wizard: a pending record
            // resumes at sign-in, a virgin install creates. No backend +
            // no credential = nothing to gate → straight to the wizard.
            AuthService auth = AuthService.Current;
            if (!auth.Configured && !auth.Gating)
            {
                ShowWizard();
                return;
            }
            var authWin = new AuthWindow(host,
                auth.HasPending || auth.Record != null
                    ? AuthMode.SignIn : AuthMode.Create);
            authWin.Closed += (_, _) =>
            {
                if (authWin.Authenticated)
                    ShowWizard();
                else
                {
                    exitCode = 1;
                    UiRuntime.Shutdown();
                }
            };
            authWin.Show();
        });

        try { ipc?.Dispose(); } catch (Exception) { }
        try { service?.Dispose(); } catch (Exception) { }
        return exitCode;
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
        UiRuntime.Run(b => b.UsePlatformDetect(), _ =>
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
        });
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
        Console.WriteLine("  cryptokey install       Copy to ~/Applications + LaunchAgent autostart");
        Console.WriteLine("  cryptokey uninstall     Remove the LaunchAgent (binary stays)");
        Console.WriteLine();
        Console.WriteLine("  --dev              enables emergency exit combo Ctrl+Opt+Shift+F12");
        Console.WriteLine("  --headless         run without windows/tray (capture+tap only)");
        Console.WriteLine("  NOTE: the lock needs Accessibility permission (event tap) —");
        Console.WriteLine("        approve the prompt in Privacy & Security → Accessibility.");
    }
}
