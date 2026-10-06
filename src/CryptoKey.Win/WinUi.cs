using Avalonia;
using CryptoKey.Ui;

namespace CryptoKey;

/// <summary>
/// Windows process composition: WinForms initialized process-wide (the
/// engine and lock surfaces are WinForms), the engine on its own thread,
/// the Avalonia UI on the main thread. First run (no config) shows the
/// onboarding wizard before the engine starts.
/// </summary>
internal static class WinUi
{
    public static int Run(KeyConfig? config, bool devMode, bool forceClassic, bool openDashboard)
    {
        // Process-wide WinForms setup (DPI mode, text rendering) must precede
        // ANY window on ANY thread — the engine's monitor and lock forms.
        ApplicationConfiguration.Initialize();
        System.Windows.Forms.Application.SetColorMode(SystemColorMode.Dark);

        EngineHost? engine = null;
        UiShell? shell = null;
        int exitCode = 0;

        try
        {
            UiRuntime.Run(b => b.UseWin32().UseSkia(), _ =>
            {
                var host = new WinUiHost();

                void StartGuard(KeyConfig cfg)
                {
                    engine = EngineHost.Start(cfg, devMode, forceClassic, line =>
                    {
                        string[] parts = line.Trim().Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length == 0 || !parts[0].Equals("open", StringComparison.OrdinalIgnoreCase))
                            return null;
                        if (shell == null)
                            return "err no dashboard";
                        Route route = Routes.Parse(parts.Length > 1 ? parts[1] : null);
                        UiRuntime.Post(() => shell?.OpenWindow(route));
                        return "ok opened";
                    });
                    if (engine.Error != null)
                    {
                        Platform.Services.UserAlerts.Warn($"CryptoKey couldn't start the guard: {engine.Error}");
                        exitCode = 1;
                        UiRuntime.Shutdown();
                        return;
                    }
                    // The engine ending (quit, panic, takeover) ends the UI too.
                    engine.Stopped += UiRuntime.Shutdown;
                    shell = new UiShell(engine.Client, host);
                    UiRuntime.InstallCrashPolicy(engine.Client.Log, () => shell?.CloseWindows());
                    if (openDashboard)
                        shell.OpenWindow();
                }

                if (config != null)
                {
                    StartGuard(config);
                    return;
                }

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
            });
        }
        catch (Exception ex)
        {
            // The Avalonia stack failed — security outranks chrome, same rule
            // as macOS: run the guard headless rather than not at all. A
            // dead install (missing Skia, broken payload) would otherwise
            // silently leave every login unguarded.
            if (engine is { Running: true })
            {
                // The loop died but the engine pump is alive — it IS the
                // guard. Keep it; the CLI stays fully functional.
                Platform.Services.UserAlerts.Warn(
                    $"CryptoKey's dashboard died ({ex.Message}) — the guard is still " +
                    "running; manage it via the cryptokey CLI.");
                while (engine.Running)
                    Thread.Sleep(500);
                return exitCode;
            }
            if (config == null)
            {
                Platform.Services.UserAlerts.Warn(
                    $"CryptoKey couldn't start its UI ({ex.Message}) — " +
                    "run 'cryptokey enroll' from a terminal first.");
                return 1;
            }
            Platform.Services.UserAlerts.Warn(
                $"CryptoKey's dashboard failed ({ex.Message}) — the guard is running " +
                "headless; manage it via the cryptokey CLI.");
            return RunHeadless(config, devMode, forceClassic);
        }

        // UI loop is over (engine stopped, or startup aborted) — make sure
        // the engine has fully torn down before the process returns.
        engine?.StopAndJoin();
        if (engine?.Running == true)
            Environment.Exit(exitCode); // wedged pump — die rather than zombie-hold the mutex
        return exitCode;
    }

    /// <summary>
    /// UI-less guard: the engine pump alone on the calling thread — the
    /// classic pre-Avalonia daemon shape, for when the UI stack can't start.
    /// </summary>
    private static int RunHeadless(KeyConfig config, bool devMode, bool forceClassic)
    {
        using var service = new GuardService(config, devMode, forceClassic);
        using var ipc = new IpcServer(service.UiDispatcher, service.DispatchCommand);
        service.Start();
        ipc.Start(service.Log);
        System.Windows.Forms.Application.Run();
        return 0;
    }
}
