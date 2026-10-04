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

    public static void SetMode(StartupMode mode)
    {
        // Clear both registrations first — exactly one mechanism may own autostart.
        using (RegistryKey? key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: true))
            key?.DeleteValue(ValueName, throwOnMissingValue: false);
        Schtasks($"/delete /f /tn {TaskName}", out _);

        switch (mode)
        {
            case StartupMode.Normal:
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(RunKeyPath))
                    key.SetValue(ValueName, $"\"{Application.ExecutablePath}\" guard");
                break;
            case StartupMode.Elevated:
                int rc = Schtasks($"/create /f /tn {TaskName} /sc onlogon /rl highest " +
                    $"/tr \"\\\"{Application.ExecutablePath}\\\" guard\"", out _);
                if (rc != 0)
                    throw new InvalidOperationException($"schtasks /create failed (exit {rc})");
                break;
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
