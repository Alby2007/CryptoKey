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

        // Quarantine: a downloaded file carries com.apple.quarantine and
        // Gatekeeper blocks it — clear it on the installed copy.
        Run("/usr/bin/xattr", "-d", "com.apple.quarantine", InstalledExe);

        File.WriteAllText(PlistPath, BuildPlist());
        Console.WriteLine($"Wrote {PlistPath}");

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
