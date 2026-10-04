namespace CryptoKey;

/// <summary>
/// Start Menu shortcut management — a plain .lnk in the per-user Programs
/// folder, written through the WScript.Shell COM object (no installer needed).
/// </summary>
internal static class ShortcutManager
{
    public static string LinkPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.StartMenu),
        "Programs", "CryptoKey.lnk");

    public static bool Exists => File.Exists(LinkPath);

    public static void SetEnabled(bool enabled)
    {
        if (!enabled)
        {
            File.Delete(LinkPath);
            return;
        }

        Directory.CreateDirectory(Path.GetDirectoryName(LinkPath)!);
        string exe = Application.ExecutablePath;

        Type shellType = Type.GetTypeFromProgID("WScript.Shell")
            ?? throw new InvalidOperationException("WScript.Shell unavailable");
        dynamic shell = Activator.CreateInstance(shellType)!;
        dynamic shortcut = shell.CreateShortcut(LinkPath);
        shortcut.TargetPath = exe;
        shortcut.Arguments = "";
        shortcut.WorkingDirectory = Path.GetDirectoryName(exe);
        shortcut.IconLocation = $"\"{exe}\",0";
        shortcut.Description = "CryptoKey — USB security key PC lock";
        shortcut.Save();
    }
}
