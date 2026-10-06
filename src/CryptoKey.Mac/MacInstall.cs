using System.Diagnostics;
using System.Text;

namespace CryptoKey;

/// <summary>
/// macOS self-install: copy the running binary into ~/Applications/CryptoKey
/// and register a per-user LaunchAgent — the Windows side's %LOCALAPPDATA%
/// install + Run-key autostart, expressed natively. The agent runs in the
/// user's Aqua session (required for display capture + the event tap) and
/// launchd becomes the outer supervisor: Crashed-only KeepAlive respawns
/// abnormal exits while clean quits stay dead; our in-app watchdog is the
/// inner layer and flock keeps any double-spawn from running twice.
/// </summary>
internal static class MacInstall
{
    private const string Label = "com.cryptokey.guard";

    private static string Home =>
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    private static string InstallDir => Path.Combine(Home, "Applications", "CryptoKey");
    private static string InstalledExe => Path.Combine(InstallDir, "cryptokey");
    private static string PlistDir => Path.Combine(Home, "Library", "LaunchAgents");
    private static string PlistPath => Path.Combine(PlistDir, Label + ".plist");
    private static string LogDir => Path.Combine(Home, "Library", "Logs", "CryptoKey");
    private static string AppBundle => Path.Combine(InstallDir, "CryptoKey.app");

    /// <summary>Install the running payload + LaunchAgent, then start it.</summary>
    public static int Install()
    {
        string? source = SelfExePath();
        if (source == null)
        {
            Console.WriteLine("Can't install a 'dotnet cryptokey.dll' run — " +
                "publish and run the cryptokey binary.");
            return 1;
        }

        Directory.CreateDirectory(InstallDir);
        Directory.CreateDirectory(PlistDir);
        Directory.CreateDirectory(LogDir);

        // Payload = the exe alone when self-contained single-file, or the
        // whole publish folder when the exe has managed/native siblings.
        string sourceDir = Path.GetDirectoryName(source)!;
        bool folderPayload = File.Exists(
            Path.Combine(sourceDir, "CryptoKey.Core.dll"));

        if (Path.GetFullPath(source) == Path.GetFullPath(InstalledExe))
        {
            Console.WriteLine($"Already installed at {InstalledExe} — " +
                "refreshing the LaunchAgent only.");
        }
        else if (File.Exists(InstalledExe) || Directory.GetFiles(InstallDir).Length > 0)
        {
            Console.Write($"Overwrite install at {InstallDir}? [y/N] ");
            string? answer = Console.ReadLine();
            if (!"y".Equals(answer?.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("Aborted.");
                return 1;
            }
            CopyPayload(source, sourceDir, folderPayload);
        }
        else
        {
            CopyPayload(source, sourceDir, folderPayload);
        }
        Run("/bin/chmod", "755", InstalledExe);

        // Quarantine: a downloaded payload carries com.apple.quarantine and
        // Gatekeeper would block it — strip it only when it's actually
        // there (a locally-built binary never carries it, and an
        // unconditional strip is the kind of call audits flag).
        if (RunQuiet("/usr/bin/xattr", "-p", "com.apple.quarantine", InstalledExe) == 0)
        {
            Run("/usr/bin/xattr", "-d", "com.apple.quarantine", InstalledExe);
            Console.WriteLine("Cleared Gatekeeper quarantine on the installed copy.");
        }

        File.WriteAllText(PlistPath, BuildPlist());
        Console.WriteLine($"Wrote {PlistPath}");

        RegisterUrlScheme();

        // Reload if already bootstrapped, then start now.
        uint uid = MacInterop.getuid();
        string domain = $"gui/{uid}";
        RunQuiet("/bin/launchctl", "bootout", $"{domain}/{Label}"); // fine if absent
        Run("/bin/launchctl", "bootstrap", domain, PlistPath);
        Run("/bin/launchctl", "kickstart", "-k", $"{domain}/{Label}");
        Console.WriteLine($"LaunchAgent {Label} bootstrapped — guard is running.");
        Console.WriteLine($"Logs: {LogDir}/guard.log");
        return 0;
    }

    /// <summary>Stop + unload the agent and remove the plist. Binary stays.</summary>
    public static int Uninstall()
    {
        uint uid = MacInterop.getuid();
        Run("/bin/launchctl", "bootout", $"gui/{uid}/{Label}");
        if (File.Exists(PlistPath))
        {
            File.Delete(PlistPath);
            Console.WriteLine($"Removed {PlistPath}");
        }
        else
        {
            Console.WriteLine("No LaunchAgent installed.");
        }
        Console.WriteLine($"Binary left at {InstalledExe} — delete it by hand if unwanted.");
        return 0;
    }

    /// <summary>True when the LaunchAgent is registered.</summary>
    public static bool IsInstalled() => File.Exists(PlistPath);

    /// <summary>
    /// The UI's "start at login" toggle — quiet variant of the CLI verbs:
    /// no prompts, no console output, returns null or the error. Enabling
    /// makes sure the installed payload exists first (the plist points at
    /// it); the agent loads at next login — it is deliberately NOT
    /// bootstrapped now (the current process is already the guard).
    /// </summary>
    public static string? SetAutostart(bool enabled)
    {
        try
        {
            Directory.CreateDirectory(PlistDir);
            uint uid = MacInterop.getuid();
            string domain = $"gui/{uid}";
            if (!enabled)
            {
                RunQuiet("/bin/launchctl", "bootout", $"{domain}/{Label}");
                if (File.Exists(PlistPath))
                    File.Delete(PlistPath);
                return null;
            }

            string? source = SelfExePath();
            if (source == null)
                return "Can't enable autostart from a 'dotnet' run — publish and install first.";
            if (Path.GetFullPath(source) != Path.GetFullPath(InstalledExe))
            {
                Directory.CreateDirectory(InstallDir);
                Directory.CreateDirectory(LogDir);
                string sourceDir = Path.GetDirectoryName(source)!;
                CopyPayload(source, sourceDir,
                    File.Exists(Path.Combine(sourceDir, "CryptoKey.Core.dll")));
                RunQuiet("/bin/chmod", "755", InstalledExe);
            }
            File.WriteAllText(PlistPath, BuildPlist());
            // If an older plist is already loaded, drop it so next login
            // picks up the fresh file.
            RunQuiet("/bin/launchctl", "bootout", $"{domain}/{Label}");
            return null;
        }
        catch (Exception ex)
        {
            return ex.Message;
        }
    }

    /// <summary>Single-file payload = copy the exe; folder payload = copy siblings too.</summary>
    private static void CopyPayload(string exe, string sourceDir, bool folderPayload)
    {
        if (!folderPayload)
        {
            File.Copy(exe, InstalledExe, overwrite: true);
            return;
        }
        foreach (string f in Directory.GetFiles(sourceDir))
        {
            string name = Path.GetFileName(f);
            if (name.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase))
                continue;
            File.Copy(f, Path.Combine(InstallDir, name), overwrite: true);
        }
    }

    /// <summary>
    /// Register cryptokey:// with LaunchServices: a bare binary can't
    /// declare a scheme — CFBundleURLTypes needs a bundle — so we build a
    /// minimal wrapper .app next to the payload (Info.plist + a MacOS
    /// symlink to the exe) and lsregister it. Reset links then open this
    /// app; its argv handler forwards the URL to a live guard or launches
    /// the GUI on the auth window's reset face.
    /// </summary>
    private static void RegisterUrlScheme()
    {
        try
        {
            string contents = Path.Combine(AppBundle, "Contents");
            string macos = Path.Combine(contents, "MacOS");
            Directory.CreateDirectory(macos);
            File.WriteAllText(Path.Combine(contents, "Info.plist"), BuildAppPlist());

            string link = Path.Combine(macos, "cryptokey");
            if (!File.Exists(link))
            {
                // Relative so the bundle stays valid if InstallDir moves —
                // MacOS/ → Contents/ → CryptoKey.app/ → InstallDir/cryptokey.
                File.CreateSymbolicLink(link, "../../../cryptokey");
            }

            RunQuiet("/System/Library/Frameworks/CoreServices.framework" +
                "/Frameworks/LaunchServices.framework/Support/lsregister",
                "-f", AppBundle);
            Console.WriteLine("Registered cryptokey:// links → CryptoKey.app.");
        }
        catch (Exception ex)
        {
            // Deep links degrade to manual 'cryptokey cryptokey://…' — not fatal.
            Console.WriteLine($"URL-scheme registration skipped: {ex.Message}");
        }
    }

    private static string BuildAppPlist()
    {
        var sb = new StringBuilder();
        sb.AppendLine("""<?xml version="1.0" encoding="UTF-8"?>""");
        sb.AppendLine("""<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">""");
        sb.AppendLine("<plist version=\"1.0\">");
        sb.AppendLine("<dict>");
        sb.AppendLine("  <key>CFBundleExecutable</key><string>cryptokey</string>");
        sb.AppendLine("  <key>CFBundleIdentifier</key><string>com.cryptokey.app</string>");
        sb.AppendLine("  <key>CFBundleName</key><string>CryptoKey</string>");
        sb.AppendLine("  <key>CFBundlePackageType</key><string>APPL</string>");
        sb.AppendLine("  <key>CFBundleURLTypes</key>");
        sb.AppendLine("  <array>");
        sb.AppendLine("    <dict>");
        sb.AppendLine("      <key>CFBundleURLName</key><string>CryptoKey deep link</string>");
        sb.AppendLine("      <key>CFBundleURLSchemes</key>");
        sb.AppendLine("      <array><string>cryptokey</string></array>");
        sb.AppendLine("    </dict>");
        sb.AppendLine("  </array>");
        sb.AppendLine("</dict>");
        sb.AppendLine("</plist>");
        return sb.ToString();
    }

    /// <summary>
    /// Path of the running payload — null when running under `dotnet`.
    /// </summary>
    private static string? SelfExePath()
    {
        string path = Environment.ProcessPath ?? "";
        string name = Path.GetFileName(path);
        return name.Equals("dotnet", StringComparison.OrdinalIgnoreCase) ? null : path;
    }

    private static string BuildPlist()
    {
        var sb = new StringBuilder();
        sb.AppendLine("""<?xml version="1.0" encoding="UTF-8"?>""");
        sb.AppendLine("""<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">""");
        sb.AppendLine("<plist version=\"1.0\">");
        sb.AppendLine("<dict>");
        sb.AppendLine($"  <key>Label</key><string>{Label}</string>");
        sb.AppendLine("  <key>ProgramArguments</key>");
        sb.AppendLine("  <array>");
        sb.AppendLine($"    <string>{Xml(InstalledExe)}</string>");
        sb.AppendLine("    <string>guard</string>");
        sb.AppendLine("  </array>");
        sb.AppendLine("  <key>RunAtLoad</key><true/>");
        // Respawn ONLY on abnormal exit — clean quits (cryptokey quit)
        // stay dead. The in-app watchdog remains the inner supervisor.
        sb.AppendLine("  <key>KeepAlive</key>");
        sb.AppendLine("  <dict><key>Crashed</key><true/></dict>");
        sb.AppendLine("  <key>ProcessType</key><string>Interactive</string>");
        sb.AppendLine("  <key>LimitLoadToSessionType</key><string>Aqua</string>");
        sb.AppendLine($"  <key>StandardOutPath</key><string>{Xml(LogDir)}/guard.log</string>");
        sb.AppendLine($"  <key>StandardErrorPath</key><string>{Xml(LogDir)}/guard.err</string>");
        sb.AppendLine("</dict>");
        sb.AppendLine("</plist>");
        return sb.ToString();
    }

    private static string Xml(string s)
        => s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;");

    /// <summary>Start the agent right now if installed — the enroll flow calls this.</summary>
    public static void KickstartIfInstalled()
    {
        if (!IsInstalled())
            return;
        uint uid = MacInterop.getuid();
        RunQuiet("/bin/launchctl", "kickstart", "-k", $"gui/{uid}/{Label}");
    }

    private static int RunQuiet(string exe, params string[] args)
    {
        var psi = new ProcessStartInfo(exe)
        {
            UseShellExecute = false,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
        };
        foreach (string a in args)
            psi.ArgumentList.Add(a);
        try
        {
            using var p = Process.Start(psi);
            p?.WaitForExit();
            return p?.ExitCode ?? -1;
        }
        catch (Exception) { return -1; }
    }

    private static int Run(string exe, params string[] args)
    {
        var psi = new ProcessStartInfo(exe) { UseShellExecute = false };
        foreach (string a in args)
            psi.ArgumentList.Add(a);
        try
        {
            using var p = Process.Start(psi);
            p?.WaitForExit();
            return p?.ExitCode ?? -1;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"{exe} failed: {ex.Message}");
            return -1;
        }
    }
}
