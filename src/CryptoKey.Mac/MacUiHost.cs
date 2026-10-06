using CryptoKey.Ui;

namespace CryptoKey;

/// <summary>
/// macOS shell integration for the shared Avalonia UI: LaunchAgent startup,
/// the Dock-icon dance while the dashboard is open, `open` for folders/URLs,
/// and the embedded tray art. Features macOS lacks (vault mount, webcam
/// captures, shortcuts, elevation) are gated upstream via
/// <see cref="PlatformCapabilities"/> — the methods here report that
/// honestly rather than pretending to work.
/// </summary>
internal sealed class MacUiHost : IUiHost
{
    public PlatformCapabilities Capabilities => MacPlatform.Capabilities;

    public bool OsPrefersReducedMotion => MacInterop.PrefersReducedMotion();

    /// <summary>The daemon never runs as root in normal use.</summary>
    public bool IsElevated => MacInterop.getuid() == 0;

    public string VersionText => $"v{CryptoKeyCli.BuildStamp}";

    /// <summary>macOS menu-bar icons are template images — one art, every state.</summary>
    public Stream TrayIcon(GuardState state)
    {
        var asm = typeof(MacUiHost).Assembly;
        string name = asm.GetManifestResourceNames()
            .First(n => n.EndsWith("tray.png", StringComparison.Ordinal));
        return asm.GetManifestResourceStream(name)!;
    }

    public Stream AppIcon() => TrayIcon(GuardState.Unlocked);

    /// <summary>No tray flyout anchoring on macOS — the menu is the panel.</summary>
    public (int X, int Y)? CursorPosition() => null;

    public void OpenFolder(string path)
        => QuietOpen(path);

    public void RevealFile(string path)
        => QuietOpen("-R", path);

    public void OpenUrl(string url)
    {
        if (url.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            || url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            QuietOpen(url);
    }

    private static void QuietOpen(params string[] args)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("/usr/bin/open")
            { UseShellExecute = false };
            foreach (string a in args)
                psi.ArgumentList.Add(a);
            System.Diagnostics.Process.Start(psi);
        }
        catch (Exception) { }
    }

    public UiStartupMode GetStartupMode()
        => MacInstall.IsInstalled() ? UiStartupMode.Normal : UiStartupMode.Off;

    public Task<string?> SetStartupModeAsync(UiStartupMode mode, Action<string> progress)
        // Elevated startup is a Windows concept — Normal/Off are the whole range.
        => Task.FromResult(MacInstall.SetAutostart(mode != UiStartupMode.Off));

    public bool ShortcutExists(UiShortcut which) => false;
    public void SetShortcut(UiShortcut which, bool enabled) { }

    public string? StartElevatedInstance() => "Not supported on macOS";

    public string CapturesDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        "Library", "Application Support", "CryptoKey", "captures");

    public void TestCamera(Action<string> log)
        => log("Webcam captures aren't available on macOS yet.");

    public CaptureInfo LatestCapture(bool webcamEnabled)
        => new(null, "Not available on macOS — tamper capture is Windows-only for now.");

    /// <summary>Show the Dock icon while the dashboard is open.</summary>
    public void MainWindowVisibilityChanged(bool visible)
        => MacInterop.SetDockVisible(visible);
}
