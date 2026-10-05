using System.Diagnostics;

namespace CryptoKey;

internal static class Program
{
    private sealed class HostVerbs : IHostVerbs
    {
        public int RunGuard(bool devMode, bool takeover, bool forceClassic)
            => Guard(devMode, takeover, forceClassic);
    }

    [STAThread]
    private static int Main(string[] args)
    {
        // Platform services must exist before ANY Core code runs — enroll,
        // status, guard, watchdog all reach ConfigStore/Platform.Services.
        Platform.Init(WinPlatform.Services);

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

        // Shared verbs (enroll, status, guard, open, lock, pause, resume,
        // quit, watchdog) — null means the verb is this host's own.
        if (CryptoKeyCli.Run(args, new HostVerbs()) is int shared)
            return shared;

        switch (args[0].ToLowerInvariant())
        {
            case "install":
                return Install(args);
            case "vault":
                return Vault(args);
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
        if (!CryptoKeyCli.TryLoadConfig(out KeyConfig? config, alertModal: true))
            return 1;
        if (config == null)
        {
            Console.WriteLine("No enrolled key — starting enroll first.");
            if (Enrollment.Run() != 0
                || !CryptoKeyCli.TryLoadConfig(out config, alertModal: true)
                || config == null)
                return 1;
        }

        using IDisposable? singleInstance =
            Platform.Services.SingleInstance.Acquire("CryptoKeyGuard", takeover);
        if (singleInstance == null)
        {
            // Guard already up — just raise its window.
            return CryptoKeyCli.SendIpc("open");
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
        Platform.Services.LockPolicies.Restore(Console.WriteLine);
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
        Platform.Services.SystemActions.ReleaseInputDesktop();
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

    private static int Guard(bool devMode, bool takeover, bool forceClassic)
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
        using var ipc = new IpcServer(service.UiDispatcher,
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
                CryptoKeyCli.SendIpc("quit");
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
        if (CryptoKeyCli.SendIpc("quit") == 0)
            Console.WriteLine("Handed off — the installed guard is live.");
        else
            // The takeover parks on the guard mutex with a 30s deadline —
            // a refused quit means it dies there and nothing hands off.
            Console.WriteLine("Quit refused — the takeover parks 30s then dies; " +
                "unlock, quit, and relaunch the installed copy yourself.");
        return 0;
    }

    /// <summary>
    /// `cryptokey vault …` — power-user/testing verbs. Mount/unmount/create go
    /// to the live guard over IPC when one's running (that's where auto-mount
    /// lives); standalone paths exist for create/status and a foreground
    /// mount for driver smoke tests.
    /// </summary>
    private static int Vault(string[] args)
    {
        string sub = args.Length > 1 ? args[1].ToLowerInvariant() : "status";
        if (!CryptoKeyCli.TryLoadConfig(out KeyConfig? config, alertModal: false))
            return 1;
        if (config == null)
        {
            Console.WriteLine("Not enrolled — run 'cryptokey enroll' first.");
            return 1;
        }

        // A running guard owns the vault lifecycle — forward through the pipe.
        bool live = IpcClient.Send("status", 400) != null;
        if (live && sub is "mount" or "unmount" or "create" or "status")
        {
            string cmd = $"vault {sub}";
            if (sub == "create" && args.Length > 2)
                cmd += " " + args[2];
            return CryptoKeyCli.SendIpc(cmd);
        }

        return sub switch
        {
            "create" => VaultCreateStandalone(config, args),
            "status" => VaultStatus(config),
            "mount" => VaultMountStandalone(config),
            "unmount" => VaultUnmount(config),
            "delete" => VaultDelete(config),
            _ => VaultUsage(),
        };
    }

    /// <summary>Feed a verified device secret into a VaultService for standalone ops.</summary>
    private static bool FeedVerifiedSecret(KeyConfig config, VaultService vault)
    {
        UsbDisk? disk;
        try
        {
            disk = Platform.Services.Usb.FindDisk(config.DeviceSerial);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"USB enumeration failed: {ex.Message}");
            return false;
        }
        if (disk == null)
        {
            Console.WriteLine("Enrolled key not present — the vault needs the device secret.");
            return false;
        }
        KeyfileCheck chk = KeyVerifier.Check(config, disk);
        if (chk.Match == SecretMatch.None || chk.Secret == null)
        {
            Console.WriteLine($"Key present but not verified ({chk.Detail}).");
            return false;
        }
        vault.KeyVerified(chk.Secret,
            (uint)(chk.Match == SecretMatch.Previous
                ? Math.Max(1, config.RotationCount - 1)
                : config.RotationCount));
        return true;
    }

    private static int VaultCreateStandalone(KeyConfig config, string[] args)
    {
        int mb = args.Length > 2 && int.TryParse(args[2], out int m)
            ? m : config.Guard.VaultSizeMb;
        using var vault = new VaultService(config, Platform.Services.VaultMounts,
            Console.WriteLine);
        if (!FeedVerifiedSecret(config, vault))
            return 1;
        return vault.TryCreate(mb, out string err)
            ? OkSay($"Vault created — {mb} MB at {vault.ImagePath}" +
                    (vault.State == VaultState.Mounted
                        ? $" (mounted at {vault.MountPoint})" : ""))
            : Fail(err);
    }

    private static int VaultStatus(KeyConfig config)
    {
        var vault = new VaultService(config, Platform.Services.VaultMounts, _ => { });
        Console.WriteLine($"Vault image:   {vault.ImagePath}");
        Console.WriteLine($"Enabled:       {config.Guard.VaultEnabled}");
        Console.WriteLine($"Auto-mount:    {config.Guard.VaultAutoMount}");
        Console.WriteLine($"Mount point:   {vault.ConfiguredMountPoint}");
        Console.WriteLine($"Driver:        {(vault.DriverPresent ? "present" : "MISSING — " + vault.DriverHint)}");
        if (!vault.ImageExists)
        {
            Console.WriteLine("State:         no image (create with 'cryptokey vault create')");
            return 0;
        }
        VaultHeader? header = VaultVolume.PeekHeader(vault.ImagePath);
        if (header == null)
        {
            Console.WriteLine("State:         unreadable/corrupt image");
            return 1;
        }
        Console.WriteLine($"State:         sealed (format v{header.Version}, " +
            $"{header.ChunkCount} chunks ~ " +
            $"{(header.ChunkCount * (long)VaultFormat.ChunkSize + VaultFormat.DataOffset) / (1024 * 1024)} MB)");
        Console.WriteLine($"Key slots:     gen {header.KeySlots[0].RotationGen} / {header.KeySlots[1].RotationGen}");
        return 0;
    }

    /// <summary>Foreground mount for driver smoke tests — Enter dismounts.</summary>
    private static int VaultMountStandalone(KeyConfig config)
    {
        using var vault = new VaultService(config, Platform.Services.VaultMounts,
            Console.WriteLine);
        if (!FeedVerifiedSecret(config, vault))
            return 1;
        if (!vault.TryMount(out string err))
            return Fail(err);
        Console.WriteLine($"Mounted at {vault.MountPoint} — press Enter to dismount.");
        Console.ReadLine();
        return 0;
    }

    private static int VaultUnmount(KeyConfig config)
    {
        // No live guard — try a driver-level unmount of the configured letter.
        var mounter = (DokanVaultMounter)Platform.Services.VaultMounts;
        if (!mounter.DriverPresent)
            return Fail("no Dokany driver — nothing to unmount");
        try
        {
            using var dokan = new DokanNet.Dokan(new DokanNet.Logging.NullLogger());
            string mp = config.Guard.VaultMountPoint.Trim().TrimEnd('\\') + "\\";
            dokan.RemoveMountPoint(mp);
            return OkSay($"Unmount requested for {mp}");
        }
        catch (Exception ex)
        {
            return Fail($"unmount failed: {ex.Message}");
        }
    }

    private static int VaultDelete(KeyConfig config)
    {
        using var vault = new VaultService(config, Platform.Services.VaultMounts, _ => { });
        return vault.TryDeleteImage(out string err)
            ? OkSay("Vault image deleted.")
            : Fail(err);
    }

    private static int VaultUsage()
    {
        Console.WriteLine("usage: cryptokey vault create [mb]|status|mount|unmount|delete");
        return 1;
    }

    private static int OkSay(string message)
    {
        Console.WriteLine(message);
        return 0;
    }

    private static int Fail(string message)
    {
        Console.WriteLine($"error: {message}");
        return 1;
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
        Console.WriteLine("  cryptokey vault …       Encrypted drive: create|status|mount|unmount|delete");
        Console.WriteLine("                          (needs the Dokany driver; create needs the key in)");
        Console.WriteLine();
        Console.WriteLine("  --dev              enables emergency exit combo Ctrl+Alt+Shift+F12");
        Console.WriteLine("  --classic          force the overlay lock (skip the private desktop)");
        Console.WriteLine("  --release-desktop  escape hatch: switch input back to the Default");
        Console.WriteLine("                     desktop if the session ever strands on the lock desktop");
    }
}
