using System.Diagnostics;
using System.IO.Compression;
using System.Reflection;

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
    /// <summary>
    /// "0.9.0+747d38b…" — version + commit of the running exe, from
    /// InformationalVersion (the SDK stamps SourceRevisionId). Compare the
    /// suffix with `git rev-parse HEAD` to tell whether the installed copy
    /// matches the repo.
    /// </summary>
    public static string BuildStamp
    {
        get
        {
            var asm = Assembly.GetEntryAssembly() ?? typeof(CryptoKeyCli).Assembly;
            return asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
                       ?.InformationalVersion ?? "0.0.0+unknown";
        }
    }

    /// <summary>%LOCALAPPDATA%\CryptoKey — the self-install target.</summary>
    public static string InstallDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "CryptoKey");

    /// <summary>The release tag this build would ship as: "v0.9.0+abc123".</summary>
    public static string ReleaseTag => "v" + BuildStamp;

    public static int? Run(string[] args, IHostVerbs host)
    {
        if (args.Length == 0)
            return null;
        switch (args[0].ToLowerInvariant())
        {
            case "enroll":
                // Re-enrollment rewrites the key/config pair — an
                // account-bound install treats it as a sensitive op. Bind
                // the on-disk config first — a bare CLI process has no
                // engine to have bound it, so the record is invisible
                // (and the verifier unusable) until we do.
                string? enrollAuth = null;
                try { AuthService.Current.BindConfig(ConfigStore.Load()); }
                catch (Exception) { }
                if (AuthService.Current.Gating && !AuthService.Current.Authorized)
                {
                    enrollAuth = ReadPassword("Account password: ");
                    string ae = enrollAuth == null ? "AUTH_REQUIRED"
                        : AuthService.Current.Authorize(enrollAuth, out string e)
                            ? "" : e;
                    if (ae.Length > 0)
                    {
                        Console.WriteLine($"error: {ae}");
                        return 1;
                    }
                }
                int erc = Enrollment.Run();
                if (erc == 0)
                {
                    // A running guard holds the old config in memory — ping it
                    // so it reloads and watches the new key's serial. The
                    // guard's own gate applies: the just-authorized password
                    // rides along when we took one.
                    string trailer = enrollAuth == null ? "" : " |auth "
                        + Convert.ToBase64String(
                            System.Text.Encoding.UTF8.GetBytes(enrollAuth));
                    _ = IpcClient.Send("reenrolled" + trailer, 400);
                }
                return erc;
            case "status":
                return Status();
            case "guard":
                return host.RunGuard(
                    args.Contains("--dev", StringComparer.OrdinalIgnoreCase),
                    args.Contains("--takeover", StringComparer.OrdinalIgnoreCase),
                    args.Contains("--classic", StringComparer.OrdinalIgnoreCase));
            case "open":
                // Optional page: `cryptokey open vault` deep-links the dashboard.
                return SendIpc(args.Length > 1 ? $"open {args[1]}" : "open");
            case "lock":
                return SendIpc("lock");
            case "auth":
                // `auth status` / `auth signout` — piped to a live guard;
                // signout is gated like any mutator.
                if (args.Length > 1
                    && args[1].Equals("signout", StringComparison.OrdinalIgnoreCase))
                    return SendIpcGated("auth signout");
                return SendIpc("auth status");
            case "pause":
                int mins = args.Length > 1 && int.TryParse(args[1], out int m) ? m : 5;
                return SendIpcGated($"pause {mins}");
            case "resume":
                return SendIpcGated("resume");
            case "quit":
                return SendIpcGated("quit");
            case "update":
                return Update(args);
            case "sign-release":
                return SignRelease(args);
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

    /// <summary>
    /// Send a mutating command through the pipe. A live account session
    /// authorizes it silently; without one the guard answers AUTH_REQUIRED
    /// and the CLI prompts for the account password (masked) and retries
    /// with a "|auth" trailer. The password never lands in argv or logs.
    /// </summary>
    public static int SendIpcGated(string command)
    {
        string? reply = IpcClient.Send(command);
        if (reply != null
            && reply.Contains("AUTH_REQUIRED", StringComparison.Ordinal))
        {
            string? pw = ReadPassword("Account password: ");
            if (pw == null)
            {
                Console.WriteLine("error: AUTH_REQUIRED — no account password supplied");
                return 1;
            }
            reply = IpcClient.Send(command + " |auth " +
                Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(pw)));
        }
        if (reply == null)
        {
            Console.WriteLine("cryptokey guard is not running.");
            return 1;
        }
        Console.WriteLine(reply);
        return reply.StartsWith("ok", StringComparison.Ordinal) ? 0 : 1;
    }

    /// <summary>
    /// Masked console password entry — '*' per char, Backspace edits,
    /// Escape cancels (returns null). A redirected stdin can't do masked
    /// reads: it falls back to a plain line so scripts still work.
    /// </summary>
    public static string? ReadPassword(string prompt)
    {
        if (Console.IsInputRedirected)
        {
            Console.Write(prompt);
            return Console.ReadLine();
        }
        try { Console.Write(prompt); }
        catch (Exception) { return null; }
        var sb = new System.Text.StringBuilder();
        while (true)
        {
            ConsoleKeyInfo k;
            try { k = Console.ReadKey(intercept: true); }
            catch (Exception) { return null; }
            if (k.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                break;
            }
            if (k.Key == ConsoleKey.Escape)
            {
                Console.WriteLine();
                return null;
            }
            if (k.Key == ConsoleKey.Backspace)
            {
                if (sb.Length > 0)
                {
                    sb.Remove(sb.Length - 1, 1);
                    Console.Write("\b \b");
                }
                continue;
            }
            if (k.KeyChar == '\0' || char.IsControl(k.KeyChar))
                continue;
            sb.Append(k.KeyChar);
            Console.Write('*');
        }
        return sb.ToString();
    }

    /// <summary>
    /// `cryptokey update [--apply]` — check GitHub for a newer signed
    /// release. --apply hands the swap to the live guard (which stages,
    /// quits, and lets the staged exe relaunch it); with no guard running
    /// it stages + spawns the swap directly. Apply is always user-driven —
    /// the app never self-replaces unprompted.
    /// </summary>
    private static int Update(string[] args)
    {
        bool apply = args.Contains("--apply", StringComparer.OrdinalIgnoreCase);
        if (apply && IpcClient.Send("update apply", 2000) is string reply)
        {
            if (reply.Contains("AUTH_REQUIRED", StringComparison.Ordinal))
            {
                string? pw = ReadPassword("Account password: ");
                if (pw == null)
                {
                    Console.WriteLine("error: AUTH_REQUIRED");
                    return 1;
                }
                reply = IpcClient.Send("update apply |auth " +
                    Convert.ToBase64String(
                        System.Text.Encoding.UTF8.GetBytes(pw)), 2000)
                    ?? "err guard went quiet";
            }
            Console.WriteLine(reply);
            return reply.StartsWith("ok") ? 0 : 1;
        }
        Console.WriteLine($"Checking github.com/{UpdateChecker.Repo} …");
        UpdateInfo? info;
        try
        {
            info = UpdateChecker.CheckAsync().GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Check failed: {ex.Message}");
            return 1;
        }
        if (info == null)
        {
            Console.WriteLine($"Up to date — this build is {BuildStamp}.");
            return 0;
        }
        Console.WriteLine($"Update: {info.TagName} " +
            $"(published {info.PublishedAt:yyyy-MM-dd})");
        if (!apply)
        {
            Console.WriteLine("Run 'cryptokey update --apply' to install it.");
            return 0;
        }
        try
        {
            // Staging is a SIBLING of the install dir — same volume for the
            // renames, but outside the tree that gets moved aside.
            string payload = UpdateChecker.FetchVerifiedAsync(info,
                InstallDir + "-staging",
                Console.WriteLine).GetAwaiter().GetResult();
            string stagedExe = Path.Combine(payload, "cryptokey.exe");
            if (!File.Exists(stagedExe))
            {
                Console.WriteLine("Staged payload is missing cryptokey.exe — aborting.");
                return 1;
            }
            Process.Start(new ProcessStartInfo(
                stagedExe, $"apply-update --target \"{InstallDir}\"")
            { UseShellExecute = true });
            Console.WriteLine("Applying — the staged copy swaps the install and relaunches it.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Update failed: {ex.Message}");
            return 1;
        }
    }

    /// <summary>
    /// `cryptokey sign-release` — maintainer/release tooling, not a user verb.
    /// `--gen-key <file.pem>` writes a fresh ECDSA-P256 private key and
    /// prints the public key to pin in ReleaseSigning.cs.
    /// `&lt;publishDir&gt; &lt;key.pem&gt;` builds cryptokey-win-x64.zip +
    /// SHA256SUMS.txt + SHA256SUMS.sig beside the publish dir — attach all
    /// three to the GitHub release. The private key never enters the repo.
    /// </summary>
    private static int SignRelease(string[] args)
    {
        if (args.Length >= 3
            && args[1].Equals("--gen-key", StringComparison.OrdinalIgnoreCase))
        {
            (string newPem, string pub) = ReleaseSigning.GenerateKeyPem();
            File.WriteAllText(args[2], newPem);
            Console.WriteLine($"Wrote {args[2]} — keep it offline, never commit it.");
            Console.WriteLine($"Pin this in ReleaseSigning.PinnedPubKeyB64:\n{pub}");
            return 0;
        }
        if (args.Length < 3)
        {
            Console.WriteLine("usage: cryptokey sign-release --gen-key <key.pem>");
            Console.WriteLine("       cryptokey sign-release <publishDir> <key.pem> [tag]");
            return 1;
        }
        string publishDir = args[1], keyPath = args[2];
        if (!File.Exists(Path.Combine(publishDir, "cryptokey.exe")))
        {
            Console.WriteLine($"{publishDir} has no cryptokey.exe — " +
                "expected a `dotnet publish` output dir.");
            return 1;
        }
        string pem = File.ReadAllText(keyPath);
        string outDir = Directory.GetParent(Path.GetFullPath(publishDir))!.FullName;
        string zipPath = Path.Combine(outDir, UpdateChecker.ZipName);
        // The tag the manifest binds to must be the GitHub release tag —
        // callers (CI) pass it explicitly; standalone defaults to this build.
        string tag = args.Length > 3 ? args[3] : ReleaseTag;
        ZipFile.CreateFromDirectory(
            publishDir, zipPath, CompressionLevel.SmallestSize, includeBaseDirectory: false);
        string manifest = $"# release: {tag}\n" +
            $"{UpdateChecker.Sha256Hex(zipPath)}  {UpdateChecker.ZipName}\n";
        string manifestPath = Path.Combine(outDir, UpdateChecker.ManifestName);
        File.WriteAllText(manifestPath, manifest);
        File.WriteAllBytes(Path.Combine(outDir, UpdateChecker.SigName),
            ReleaseSigning.Sign(System.Text.Encoding.UTF8.GetBytes(manifest), pem));
        Console.WriteLine($"Signed {tag}:");
        Console.WriteLine($"  {zipPath}");
        Console.WriteLine($"  {manifestPath}");
        Console.WriteLine($"  {Path.Combine(outDir, UpdateChecker.SigName)}");
        Console.WriteLine($"Attach all three to GitHub release {tag} — the " +
            "manifest binds that tag; a different release tag gets refused.");
        return 0;
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

        Console.WriteLine($"CryptoKey:     {BuildStamp}");
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
