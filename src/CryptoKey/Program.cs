using System.Diagnostics;

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

        // Manual escape hatch for a stranded secure-desktop lock: pulls input
        // back to the user's desktop. Works even while the guard is running —
        // independent of IPC, hooks, and the lock thread.
        if (args.Length >= 1 && args[0].Equals("--release-desktop", StringComparison.OrdinalIgnoreCase))
            return ReleaseDesktop();

        // Dead-man's switch for the secure-desktop lock: spawned by
        // SecureLockSurface before SwitchDesktop. A killed/crashed guard does
        // NOT make Windows return the input desktop on its own — this tiny
        // process waits for the parent to die, then pulls input back.
        if (args.Length >= 2 && args[0].Equals("--lock-watchdog", StringComparison.OrdinalIgnoreCase)
            && int.TryParse(args[1], out int parentPid))
            return RunLockWatchdog(parentPid);

        // Dev/internal: writes the app icon (committed as app.ico) using the
        // same renderer as the tray — badge in the system accent color.
        if (args.Length >= 2 && args[0].Equals("--export-icon", StringComparison.OrdinalIgnoreCase))
        {
            File.WriteAllBytes(args[1],
                TrayIcons.BuildIcoBytes(Theme.Accent, TrayIcons.ShellSizes));
            Console.WriteLine($"Wrote {args[1]} ({TrayIcons.ShellSizes.Length} PNG frames).");
            return 0;
        }

        // Bare `cryptokey` (optionally `--dev`) = desktop app: guard + dashboard.
        if (args.Length == 0 || args[0].StartsWith("--"))
            return Gui(args.Contains("--dev", StringComparer.OrdinalIgnoreCase),
                args.Contains("--takeover", StringComparer.OrdinalIgnoreCase),
                args.Contains("--classic", StringComparer.OrdinalIgnoreCase));

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
                    args.Contains("--takeover", StringComparer.OrdinalIgnoreCase),
                    args.Contains("--classic", StringComparer.OrdinalIgnoreCase));
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
            case "install":
                return Install(args);
            case "watchdog":
                // Internal process role — spawned by the guard's Supervisor,
                // not a user-facing command. --dev/--classic are forwarded
                // to every guard it respawns.
                if (args.Length >= 3
                    && args[1].Equals("--parent", StringComparison.OrdinalIgnoreCase)
                    && int.TryParse(args[2], out int guardPid))
                    return Watchdog.Run(guardPid,
                        args.Contains("--dev", StringComparer.OrdinalIgnoreCase),
                        args.Contains("--classic", StringComparer.OrdinalIgnoreCase));
                Console.WriteLine("usage: cryptokey watchdog --parent <pid>");
                return 1;
            case "help":
                Usage();
                return 0;
            default:
                Usage();
                return 1;
        }
    }

    private static int Gui(bool devMode, bool takeover, bool forceClassic)
    {
        if (!TryLoadConfig(out KeyConfig? config, alertModal: true))
            return 1;
        if (config == null)
        {
            Console.WriteLine("No enrolled key — starting enroll first.");
            if (Enrollment.Run() != 0
                || !TryLoadConfig(out config, alertModal: true)
                || config == null)
                return 1;
        }

        using Mutex singleInstance = AcquireGuardMutex(takeover, out bool createdNew);
        if (!createdNew)
        {
            // Guard already up — just raise its window.
            return SendIpc("open");
        }

        return RunApp(config, devMode, openDashboard: true, forceClassic);
    }

    /// <summary>
    /// Independent recovery for the secure-desktop lock: switches input back
    /// to the user's Default desktop. If the guard is still alive and locked,
    /// it simply re-switches on its next engage — this command only repairs
    /// the case where the process died (or wedged) while the session was on
    /// the private desktop.
    /// </summary>
    private static int ReleaseDesktop()
    {
        // Self-documenting: a LIVE locked guard treats the switch as a
        // hostile flap and yanks input back inside one poll (~300ms) — so
        // say so up front. This rescue only matters for dead-guard strands.
        string? live = IpcClient.Send("status", 400);
        if (live?.Contains("state=locked", StringComparison.OrdinalIgnoreCase) == true)
            Console.WriteLine("Guard is still locked — the flap monitor re-captures " +
                "input in ~300ms. This rescue is for dead-guard sessions.");

        // The rescue hatch frees everything the lock applied — including
        // lock policies, which a died-while-locked guard can leave behind.
        LockPolicies.Restore(Console.WriteLine);
        IntPtr h = NativeMethods.OpenDesktop("Default", 0, false,
            NativeMethods.DESKTOP_SWITCHDESKTOP);
        if (h == IntPtr.Zero)
        {
            Console.WriteLine("Could not open the Default desktop.");
            return 1;
        }
        try
        {
            if (!NativeMethods.SwitchDesktop(h))
            {
                Console.WriteLine("SwitchDesktop to Default failed.");
                return 1;
            }
            Console.WriteLine("Input switched back to the Default desktop.");
            return 0;
        }
        finally
        {
            NativeMethods.CloseDesktop(h);
        }
    }

    /// <summary>
    /// Waits for the guard process to exit, then switches input back to the
    /// Default desktop. Killed by <see cref="SecureLockSurface"/> on clean
    /// disengage — reaching the switch means the guard died while the session
    /// was (possibly) on the private desktop. Best-effort and silent: it runs
    /// detached with no console and nobody to report to.
    /// </summary>
    private static int RunLockWatchdog(int parentPid)
    {
        HideConsoleIfOwned();
        try
        {
            using var parent = Process.GetProcessById(parentPid);
            parent.WaitForExit();
        }
        catch (Exception)
        {
            // Parent already gone (or pid was never valid) — that's the
            // failure case we're here for, so still try to release.
        }
        try
        {
            IntPtr h = NativeMethods.OpenDesktop("Default", 0, false,
                NativeMethods.DESKTOP_SWITCHDESKTOP);
            if (h != IntPtr.Zero)
            {
                NativeMethods.SwitchDesktop(h);
                NativeMethods.CloseDesktop(h);
            }
        }
        catch (Exception) { }
        return 0;
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

    private static int Guard(bool devMode, bool takeover, bool forceClassic)
    {
        if (!TryLoadConfig(out KeyConfig? config, alertModal: true))
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

        return RunApp(config, devMode, openDashboard: false, forceClassic);
    }

    // Shared body for the desktop app and the tray-only daemon: the only
    // difference is whether the dashboard opens on launch. Hiding the console
    // matters most here — both autostart modes invoke `guard`, and without
    // this a console window pops up at every login.
    private static int RunApp(KeyConfig config, bool devMode, bool openDashboard,
        bool forceClassic)
    {
        HideConsoleIfOwned();
        ApplicationConfiguration.Initialize();
        Application.SetColorMode(SystemColorMode.Dark);
        Animator.Enabled = config.Guard.Animations;

        using var service = new GuardService(config, devMode, forceClassic);
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
        ipc.Start(service.Log);
        if (openDashboard)
            shell.OpenWindow();
        Application.Run();
        return 0;
    }

    /// <summary>
    /// Self-install: copies the running payload into %LOCALAPPDATA%\CryptoKey
    /// and repoints shortcuts + autostart at the installed exe — so the
    /// desktop icon and Start-with-Windows survive a `dotnet clean` of the
    /// build tree. Finally offers a live handoff: spawn the installed copy
    /// with --takeover (it parks on the guard mutex), quit the old guard, and
    /// the new one claims it with no unguarded gap.
    /// </summary>
    private static int Install(string[] args)
    {
        string targetDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "CryptoKey");
        string sourceDir = Path.GetFullPath(AppContext.BaseDirectory)
            .TrimEnd(Path.DirectorySeparatorChar);
        string installedExe = Path.Combine(targetDir, "cryptokey.exe");

        // Flags the relaunch/handoff paths forward so a --dev guard doesn't
        // silently lose its panic combo.
        string modeFlags =
            (args.Contains("--dev", StringComparer.OrdinalIgnoreCase) ? " --dev" : "") +
            (args.Contains("--classic", StringComparer.OrdinalIgnoreCase) ? " --classic" : "");

        bool relaunchInstalled = false;
        if (sourceDir.Equals(targetDir, StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine($"Already running from {targetDir} — skipping the copy.");
        }
        else if (sourceDir.StartsWith(targetDir + Path.DirectorySeparatorChar,
            StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine($"Refusing: {sourceDir} is inside the install dir — " +
                "the copy would recurse into itself.");
            return 1;
        }
        else
        {
            try
            {
                CopyTree(sourceDir, targetDir);
                Console.WriteLine($"Installed {sourceDir}\n  -> {targetDir}");
            }
            catch (Exception ex)
            {
                // A guard running from the install dir locks its own files —
                // offer to quit it and retry rather than making the user
                // discover the ordering themselves.
                string? live0 = IpcClient.Send("status", 400);
                if (live0 == null
                    || live0.Contains("state=locked", StringComparison.OrdinalIgnoreCase)
                    || !Ask("The installed guard is running — quit it and retry the copy?"))
                {
                    Console.WriteLine($"Install failed: {ex.Message}");
                    Console.WriteLine(live0?.Contains("state=locked",
                        StringComparison.OrdinalIgnoreCase) == true
                        ? "(Unlock first — quit is refused while locked.)"
                        : "(Quit the running guard first.)");
                    return 1;
                }
                SendIpc("quit");
                // Release takes a beat — hooks teardown, mutex drop, process exit.
                for (int i = 0; i < 20; i++)
                {
                    Thread.Sleep(300);
                    try
                    {
                        CopyTree(sourceDir, targetDir);
                        relaunchInstalled = true;
                        break;
                    }
                    catch (Exception) { }
                }
                if (!relaunchInstalled)
                {
                    Console.WriteLine("Copy still blocked after the guard quit — files stayed locked.");
                    return 1;
                }
                Console.WriteLine($"Installed {sourceDir}\n  -> {targetDir}");
            }
        }

        // Shortcuts repoint at the installed exe — IconLocation rides along,
        // so the embedded padlock survives the move.
        try
        {
            ShortcutManager.SetEnabled(ShortcutTarget.StartMenu, true, installedExe);
            ShortcutManager.SetEnabled(ShortcutTarget.Desktop, true, installedExe);
            Console.WriteLine("Shortcuts repointed (Start Menu + Desktop).");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Shortcut repoint failed: {ex.Message}");
        }

        // Re-register autostart only if a mode is already armed — install
        // never turns startup on by itself.
        try
        {
            switch (StartupManager.GetMode())
            {
                case StartupMode.Normal:
                    StartupManager.SetMode(StartupMode.Normal, installedExe);
                    Console.WriteLine("Autostart (Run key) repointed to the installed exe.");
                    break;
                case StartupMode.Elevated:
                    // The scheduled task needs admin to rewrite — spawn the
                    // INSTALLED exe as the elevated helper, so what it
                    // registers as its own ExecutablePath is the new path.
                    Process.Start(new ProcessStartInfo(installedExe, "--set-startup elevated")
                    { UseShellExecute = true, Verb = "runas" });
                    Console.WriteLine("Autostart is elevated — approve the UAC prompt to repoint it.");
                    break;
                default:
                    Console.WriteLine("Autostart: off — nothing to repoint.");
                    break;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Autostart repoint failed: {ex.Message}");
        }

        // The quit-to-refresh path killed the guard to free the files —
        // put the freshly-installed copy back without another prompt,
        // keeping its mode flags.
        if (relaunchInstalled)
        {
            Process.Start(new ProcessStartInfo(installedExe, modeFlags.TrimStart())
            { UseShellExecute = true });
            Console.WriteLine("Relaunched the installed copy.");
            return 0;
        }

        string? live = IpcClient.Send("status", 400);
        if (live == null)
        {
            if (Ask("No guard running — launch the installed app now?"))
                Process.Start(new ProcessStartInfo(installedExe) { UseShellExecute = true });
            return 0;
        }
        if (live.Contains("state=locked", StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine("Guard is locked — install is in place; unlock and " +
                "'cryptokey quit' to hand off to the installed copy.");
            return 0;
        }
        if (!Ask("Hand the running guard over to the installed copy?"))
        {
            Console.WriteLine("Installed. The running guard still uses the old exe — " +
                "quit + relaunch it when ready.");
            return 0;
        }

        // Bare exe --takeover (not "guard --takeover") — a GUI guard should
        // hand off to a GUI guard so the tray app survives the switch.
        string takeArgs = "--takeover" + modeFlags;
        Process.Start(new ProcessStartInfo(installedExe, takeArgs)
        { UseShellExecute = false, CreateNoWindow = true });
        if (SendIpc("quit") == 0)
            Console.WriteLine("Handed off — the installed guard is live.");
        else
            // The takeover parks on the guard mutex with a 30s deadline —
            // a refused quit means it dies there and nothing hands off.
            Console.WriteLine("Quit refused — the takeover parks 30s then dies; " +
                "unlock, quit, and relaunch the installed copy yourself.");
        return 0;
    }

    /// <summary>[Y/n] prompt — a redirected/piped stdin counts as yes.</summary>
    private static bool Ask(string question)
    {
        Console.Write($"{question} [Y/n] ");
        string? ans = Console.ReadLine();
        return ans == null || ans.Trim().Length == 0
            || ans.Trim().Equals("y", StringComparison.OrdinalIgnoreCase);
    }

    private static void CopyTree(string source, string target)
    {
        Directory.CreateDirectory(target);
        foreach (string f in Directory.GetFiles(source))
            File.Copy(f, Path.Combine(target, Path.GetFileName(f)), overwrite: true);
        foreach (string d in Directory.GetDirectories(source))
            CopyTree(d, Path.Combine(target, Path.GetFileName(d)));
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

    private static bool TryLoadConfig(out KeyConfig? config, bool alertModal = false)
    {
        try
        {
            config = ConfigStore.Load(out bool restoredFromBackup);
            if (ConfigStore.LastRestoreFromRegistry)
                Alert("CryptoKey's config directory was wiped — the config was " +
                    "restored from the registry backup. If you didn't delete it, " +
                    "treat this as a tamper event.", alertModal);
            else if (restoredFromBackup)
                Alert("CryptoKey's config.json was corrupt — restored the last-good " +
                    "backup (config.json.bak). The corrupt file was quarantined as " +
                    "config.json.bad.", alertModal);
            return true;
        }
        catch (Exception ex)
        {
            // Autostart/scheduled launches hide the console — without a modal
            // alert a corrupt config means "booted with no protection and no
            // sign", which is the worst failure shape this app can have.
            Alert($"CryptoKey config at {ConfigStore.ConfigPath} is corrupt and no " +
                $"usable backup exists ({ex.Message}). Run 'cryptokey enroll' to " +
                "re-enroll — the guard will not start without a config.", alertModal);
            config = null;
            return false;
        }
    }

    private static void Alert(string message, bool modal)
    {
        Console.WriteLine(message);
        if (modal)
            MessageBox.Show(message, "CryptoKey",
                MessageBoxButtons.OK, MessageBoxIcon.Warning);
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
        Console.WriteLine($"Unlock policy: {config.Guard.UnlockPolicy}" +
            (config.Guard.StrictTamper ? " (strict tamper)" : ""));
        Console.WriteLine($"Lock mode:     {config.Guard.LockMode}");

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
            Console.WriteLine(ok ? $"Keyfile:       {detail}" : $"Keyfile:       FAILED ({detail})");
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
        Console.WriteLine("  cryptokey install       Copy the app to %LOCALAPPDATA%\\CryptoKey and");
        Console.WriteLine("                          repoint shortcuts + autostart at it");
        Console.WriteLine();
        Console.WriteLine("  --dev              enables emergency exit combo Ctrl+Alt+Shift+F12");
        Console.WriteLine("  --classic          force the overlay lock (skip the private desktop)");
        Console.WriteLine("  --release-desktop  escape hatch: switch input back to the Default");
        Console.WriteLine("                     desktop if the session ever strands on the lock desktop");
    }
}
