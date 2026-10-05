namespace CryptoKey;

/// <summary>Host-specific verb hooks — the pump-carrying guard run is the host's.</summary>
internal interface IHostVerbs
{
    /// <summary>Run the platform guard (message pump, tray, lock surfaces).</summary>
    int RunGuard(bool devMode, bool takeover, bool forceClassic);
}

/// <summary>
/// The shared verb table — dispatch for the commands every host speaks.
/// Platform services must be initialized (<see cref="Platform.Init"/>) before
/// this is called. Returns null for verbs the host owns (install, GUI launch,
/// OS-specific internal roles) so its own dispatch can continue.
/// </summary>
internal static class CryptoKeyCli
{
    public static int? Run(string[] args, IHostVerbs host)
    {
        if (args.Length == 0)
            return null;
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
                return host.RunGuard(
                    args.Contains("--dev", StringComparer.OrdinalIgnoreCase),
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
            default:
                return null;
        }
    }

    public static int SendIpc(string command)
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

    /// <summary>Shared load + alert path — corrupt/no-config handling everywhere.</summary>
    public static bool TryLoadConfig(out KeyConfig? config, bool alertModal = false)
    {
        try
        {
            config = ConfigStore.Load(out bool restoredFromBackup);
            if (ConfigStore.LastRestoreFromBackup)
                Alert("CryptoKey's config directory was wiped — the config was " +
                    "restored from the third-copy backup. If you didn't delete it, " +
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
            Platform.Services.UserAlerts.Warn(message);
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
            disk = Platform.Services.Usb.FindDisk(config.DeviceSerial);
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
            string volumes = disk.VolumePaths.Count > 0 ? string.Join(", ", disk.VolumePaths) : "(no volume)";
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
}
