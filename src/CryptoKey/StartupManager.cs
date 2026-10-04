using System.Diagnostics;
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
        if (Schtasks("/query /tn CryptoKey") == 0)
            return StartupMode.Elevated;
        using RegistryKey? key = Registry.CurrentUser.OpenSubKey(RunKeyPath);
        return key?.GetValue(ValueName) != null ? StartupMode.Normal : StartupMode.Off;
    }

    public static void SetMode(StartupMode mode)
    {
        // Clear both registrations first — exactly one mechanism may own autostart.
        using (RegistryKey? key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: true))
            key?.DeleteValue(ValueName, throwOnMissingValue: false);
        Schtasks("/delete /f /tn CryptoKey");

        switch (mode)
        {
            case StartupMode.Normal:
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(RunKeyPath))
                    key.SetValue(ValueName, $"\"{Application.ExecutablePath}\" guard");
                break;
            case StartupMode.Elevated:
                int rc = Schtasks("/create /f /tn CryptoKey /sc onlogon /rl highest " +
                    $"/tr \"\\\"{Application.ExecutablePath}\\\" guard\"");
                if (rc != 0)
                    throw new InvalidOperationException($"schtasks /create failed (exit {rc})");
                break;
        }
    }

    private static int Schtasks(string arguments)
    {
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
            p.WaitForExit(10000);
            return p.ExitCode;
        }
        catch (Exception)
        {
            return -1;
        }
    }
}
