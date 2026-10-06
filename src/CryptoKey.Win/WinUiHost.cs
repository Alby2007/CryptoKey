using System.Diagnostics;
using System.Security.Principal;
using CryptoKey.Ui;

namespace CryptoKey;

/// <summary>
/// Windows shell integration for the shared Avalonia UI: Run-key/Scheduled-
/// Task startup (with the UAC helper hand-off), .lnk shortcuts, the webcam
/// capture store, Explorer, and the GDI-rendered state icons.
/// </summary>
internal sealed class WinUiHost : IUiHost
{
    private readonly TrayIcons _icons = new();

    public PlatformCapabilities Capabilities => WinPlatform.Capabilities;

    public bool OsPrefersReducedMotion
    {
        get
        {
            bool animate = true;
            try
            {
                if (NativeMethods.SystemParametersInfo(NativeMethods.SPI_GETCLIENTAREAANIMATION, 0, ref animate, 0))
                    return !animate;
            }
            catch (Exception) { }
            return false;
        }
    }

    public bool IsElevated { get; } =
        new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

    public string VersionText => $"v{CryptoKeyCli.BuildStamp}";

    public Stream TrayIcon(GuardState state)
    {
        var ms = new MemoryStream();
        _icons.For(state).Save(ms);
        ms.Position = 0;
        return ms;
    }

    public Stream AppIcon()
    {
        var ms = new MemoryStream();
        TrayIcons.App.Save(ms);
        ms.Position = 0;
        return ms;
    }

    public (int X, int Y)? CursorPosition()
        => NativeMethods.GetCursorPos(out NativeMethods.POINT p) ? (p.X, p.Y) : null;

    public void OpenFolder(string path)
    {
        try
        {
            Directory.CreateDirectory(path);
            Process.Start(new ProcessStartInfo("explorer.exe", $"\"{path}\"") { UseShellExecute = true });
        }
        catch (Exception) { }
    }

    public void RevealFile(string path)
    {
        try { Process.Start("explorer.exe", $"/select,\"{path}\""); }
        catch (Exception) { }
    }

    public void OpenUrl(string url)
    {
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); }
        catch (Exception) { }
    }

    public UiStartupMode GetStartupMode() => StartupManager.GetMode() switch
    {
        StartupMode.Elevated => UiStartupMode.Elevated,
        StartupMode.Normal => UiStartupMode.Normal,
        _ => UiStartupMode.Off,
    };

    public async Task<string?> SetStartupModeAsync(UiStartupMode mode, Action<string> progress)
    {
        StartupMode target = mode switch
        {
            UiStartupMode.Elevated => StartupMode.Elevated,
            UiStartupMode.Normal => StartupMode.Normal,
            _ => StartupMode.Off,
        };
        // Writing (or removing) an elevated scheduled task needs admin —
        // hand it to an elevated helper instance instead of failing on
        // Access denied.
        if (!IsElevated && (target == StartupMode.Elevated || StartupManager.GetMode() == StartupMode.Elevated))
        {
            Process? p;
            try
            {
                p = Process.Start(new ProcessStartInfo(Environment.ProcessPath!,
                        $"--set-startup {target.ToString().ToLowerInvariant()}")
                {
                    UseShellExecute = true,
                    Verb = "runas",
                });
            }
            catch (Exception ex)
            {
                return $"Elevation cancelled: {ex.Message}";
            }
            if (p == null)
                return "Elevation helper did not start";
            progress("Approve the administrator prompt to apply the startup change…");
            // WaitForExit's bool first — ExitCode throws on a still-running
            // process (UAC left up >90s).
            bool ok = await Task.Run(() =>
            {
                using (p)
                    return p.WaitForExit(90000) && p.ExitCode == 0;
            });
            return ok ? null : "Startup change cancelled or failed";
        }
        try
        {
            StartupManager.SetMode(target);
            return null;
        }
        catch (Exception ex)
        {
            return $"Startup change failed: {ex.Message}";
        }
    }

    private static ShortcutTarget Map(UiShortcut s)
        => s == UiShortcut.Desktop ? ShortcutTarget.Desktop : ShortcutTarget.StartMenu;

    public bool ShortcutExists(UiShortcut which) => ShortcutManager.Exists(Map(which));

    public void SetShortcut(UiShortcut which, bool enabled) => ShortcutManager.SetEnabled(Map(which), enabled);

    public string? StartElevatedInstance()
    {
        try
        {
            var p = Process.Start(new ProcessStartInfo(Environment.ProcessPath!, "--takeover")
            {
                UseShellExecute = true,
                Verb = "runas",
            });
            if (p == null)
                return "Elevated instance did not start";
            // Give the child a beat to die on its own startup errors before we
            // release the mutex — a failed takeover would otherwise leave the
            // machine silently unguarded.
            using (p)
            {
                if (p.WaitForExit(2500))
                    return $"Elevated launch failed (exit {p.ExitCode})";
            }
            return null;
        }
        catch (Exception ex)
        {
            return $"Elevation cancelled: {ex.Message}";
        }
    }

    public string CapturesDir => CaptureService.CapturesDir;

    public void TestCamera(Action<string> log) => CaptureService.Snap("test", log);

    public CaptureInfo LatestCapture(bool webcamEnabled)
    {
        try
        {
            FileInfo? newest = Directory.Exists(CaptureService.CapturesDir)
                ? new DirectoryInfo(CaptureService.CapturesDir).EnumerateFiles()
                    .OrderByDescending(f => f.CreationTimeUtc)
                    .FirstOrDefault()
                : null;
            if (newest == null)
                return new CaptureInfo(null, webcamEnabled
                    ? "No captures yet — the first tamper event writes one (sealed to this user)."
                    : "Off — turn on “Webcam snapshot on tamper events” above.");
            // .cap files are DPAPI-sealed; legacy cleartext captures pass through.
            byte[]? bytes = CaptureService.TryOpenCapture(newest.FullName);
            return bytes != null
                ? new CaptureInfo(bytes, $"{newest.CreationTime:MMM d, HH:mm} · {newest.Length / 1024} KB · sealed to this user")
                : new CaptureInfo(null, $"{newest.Name} — unreadable (sealed or corrupt).");
        }
        catch (Exception ex)
        {
            return new CaptureInfo(null, $"Captures unreadable: {ex.Message}");
        }
    }

    public void MainWindowVisibilityChanged(bool visible) { }
}
