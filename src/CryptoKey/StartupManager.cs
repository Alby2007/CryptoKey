using Microsoft.Win32;

namespace CryptoKey;

/// <summary>
/// "Start with Windows" backed by the per-user Run key — the registry value
/// is the source of truth, so no config flag can drift out of sync.
/// Registers `cryptokey.exe guard` (tray-only, no window) at login.
/// </summary>
internal static class StartupManager
{
    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "CryptoKey";

    public static bool IsEnabled
    {
        get
        {
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(RunKeyPath);
            return key?.GetValue(ValueName) != null;
        }
    }

    public static void SetEnabled(bool enabled)
    {
        using RegistryKey key = Registry.CurrentUser.CreateSubKey(RunKeyPath);
        if (enabled)
            key.SetValue(ValueName, $"\"{Application.ExecutablePath}\" guard");
        else
            key.DeleteValue(ValueName, throwOnMissingValue: false);
    }
}
