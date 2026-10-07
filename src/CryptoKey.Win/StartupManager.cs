using System.Diagnostics;
using System.Xml.Linq;
using Microsoft.Win32;

namespace CryptoKey;

internal enum StartupMode
{
    Off,
    Normal,     // per-user Run key — silent, standard rights
    Elevated,   // Scheduled Task with highest privileges — covers elevated windows
}

/// <summary>
/// "Start with Windows" backed by the per-user Run key, or a Scheduled Task
/// (highest privileges) for elevated mode. The registrations themselves are
/// the source of truth — no config flag can drift out of sync. Both modes
/// launch `cryptokey.exe guard` (tray-only, no window) at login.
/// </summary>
internal static class StartupManager
{
    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "CryptoKey";
    private const string TaskName = "CryptoKey";

    public static StartupMode GetMode()
    {
        if (ElevatedTaskAlive())
            return StartupMode.Elevated;
        using RegistryKey? key = Registry.CurrentUser.OpenSubKey(RunKeyPath);
        return RunValueAlive(key?.GetValue(ValueName) as string)
            ? StartupMode.Normal : StartupMode.Off;
    }

    // Existence alone would lie: a disabled task, or one whose exe was moved
    // or deleted, is dead autostart — not "Elevated".
    private static bool ElevatedTaskAlive()
    {
        if (Schtasks($"/query /tn {TaskName} /xml", out string xml) != 0)
            return false;
        try
        {
            var nodes = XDocument.Parse(xml).Descendants().ToList();
            string? enabled = nodes.FirstOrDefault(e => e.Name.LocalName == "Enabled")?.Value;
            if (bool.TryParse(enabled, out bool en) && !en)
                return false;
            string? command = nodes.FirstOrDefault(e => e.Name.LocalName == "Command")?.Value;
            return command == null || File.Exists(command.Trim().Trim('"'));
        }
        catch (Exception)
        {
            return true; // task exists but its XML is unreadable — assume armed
        }
    }

    private static bool RunValueAlive(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return false;
        // Expected shape: "C:\path\cryptokey.exe" guard — a value pointing at
        // a deleted exe is dead autostart even though the value exists.
        int close = value.IndexOf('"', 1);
        string exe = close > 1 ? value[1..close] : value.Trim('"', ' ');
        return File.Exists(exe);
    }

    /// <param name="exePath">Exe the registration points at — the installer
    /// passes the installed copy's path; default is the running process.</param>
    public static void SetMode(StartupMode mode, string? exePath = null)
    {
        string exe = exePath ?? Application.ExecutablePath;
        // Clear both registrations first — exactly one mechanism may own autostart.
        using (RegistryKey? key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: true))
            key?.DeleteValue(ValueName, throwOnMissingValue: false);
        Schtasks($"/delete /f /tn {TaskName}", out _);

        switch (mode)
        {
            case StartupMode.Normal:
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(RunKeyPath))
                    key.SetValue(ValueName, $"\"{exe}\" guard");
                break;
            case StartupMode.Elevated:
                // /rl highest + a user-writable exe = a logon-time privesc:
                // any medium-IL process could swap the payload the task
                // runs. Refuse unless the exe sits under machine-protected
                // paths — the elevated helper copies it there first.
                if (IsUserWritableLocation(exe))
                    throw new InvalidOperationException(
                        $"Elevated autostart needs a Program Files install — '{exe}' is user-writable.");
                int rc = Schtasks($"/create /f /tn {TaskName} /sc onlogon /rl highest " +
                    $"/tr \"\\\"{exe}\\\" guard\"", out _);
                if (rc != 0)
                    throw new InvalidOperationException($"schtasks /create failed (exit {rc})");
                break;
        }
    }

    /// <summary>
    /// True when the path lives somewhere a medium-IL process can write —
    /// i.e. anywhere that ISN'T Program Files or Windows. An elevated
    /// scheduled task may only point at machine-protected locations.
    /// </summary>
    public static bool IsUserWritableLocation(string path)
    {
        string full;
        try { full = Path.GetFullPath(path); }
        catch (Exception) { return true; } // unparseable — treat as unsafe
        foreach (string root in MachineProtectedRoots())
        {
            if (full.StartsWith(root + Path.DirectorySeparatorChar,
                    StringComparison.OrdinalIgnoreCase))
                return false;
        }
        return true;
    }

    private static IEnumerable<string> MachineProtectedRoots()
    {
        foreach (string? root in new[]
        {
            Environment.GetEnvironmentVariable("ProgramW6432"),
            Environment.GetEnvironmentVariable("ProgramFiles"),
            Environment.GetEnvironmentVariable("ProgramFiles(x86)"),
            Environment.GetEnvironmentVariable("WINDIR"),
        })
        {
            if (!string.IsNullOrEmpty(root))
                yield return Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar);
        }
    }

    private static int Schtasks(string arguments, out string output)
    {
        output = "";
        try
        {
            using var p = Process.Start(new ProcessStartInfo("schtasks.exe", arguments)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });
            if (p == null)
                return -1;
            // Drain both streams concurrently — a full pipe buffer can
            // deadlock the child while we sit in WaitForExit.
            Task<string> stdout = p.StandardOutput.ReadToEndAsync();
            Task<string> stderr = p.StandardError.ReadToEndAsync();
            if (!p.WaitForExit(10000))
            {
                try { p.Kill(); } catch { }
                return -1; // timed out — ExitCode would throw on a live process
            }
            output = stdout.GetAwaiter().GetResult() + stderr.GetAwaiter().GetResult();
            return p.ExitCode;
        }
        catch (Exception)
        {
            return -1;
        }
    }
}
