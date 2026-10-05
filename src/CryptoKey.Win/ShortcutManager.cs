namespace CryptoKey;

/// <summary>Which shell location a .lnk lives in.</summary>
internal enum ShortcutTarget
{
    StartMenu,
    Desktop,
}

/// <summary>
/// Shortcut management — plain .lnk files in the per-user Programs folder
/// and on the Desktop, written through the WScript.Shell COM object (no
/// installer needed). DesktopDirectory (not Desktop) is the physical folder
/// and follows OneDrive desktop redirection.
/// </summary>
internal static class ShortcutManager
{
    public static string StartMenuLinkPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.StartMenu),
        "Programs", "CryptoKey.lnk");

    public static string DesktopLinkPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
        "CryptoKey.lnk");

    private static string LinkPath(ShortcutTarget target)
        => target == ShortcutTarget.Desktop ? DesktopLinkPath : StartMenuLinkPath;

    public static bool Exists(ShortcutTarget target) => File.Exists(LinkPath(target));

    /// <param name="exePath">Exe the shortcut targets — the installer passes
    /// the installed copy's path; default is the running process.</param>
    public static void SetEnabled(ShortcutTarget target, bool enabled, string? exePath = null)
    {
        string link = LinkPath(target);
        if (!enabled)
        {
            File.Delete(link);
            return;
        }

        Directory.CreateDirectory(Path.GetDirectoryName(link)!);
        string exe = exePath ?? Application.ExecutablePath;

        Type shellType = Type.GetTypeFromProgID("WScript.Shell")
            ?? throw new InvalidOperationException("WScript.Shell unavailable");
        dynamic shell = Activator.CreateInstance(shellType)!;
        dynamic shortcut = shell.CreateShortcut(link);
        shortcut.TargetPath = exe;
        shortcut.Arguments = "";
        shortcut.WorkingDirectory = Path.GetDirectoryName(exe);
        shortcut.IconLocation = $"\"{exe}\",0";
        shortcut.Description = "CryptoKey — USB security key PC lock";
        shortcut.Save();
    }
}
