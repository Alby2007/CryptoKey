namespace CryptoKey.Ui;

/// <summary>Login-startup mode as the UI presents it.</summary>
internal enum UiStartupMode
{
    Off,
    Normal,
    Elevated,
}

internal enum UiShortcut
{
    StartMenu,
    Desktop,
}

/// <summary>Newest tamper capture for the Alerts page: image bytes (null if
/// unreadable or none) plus an honest one-line note.</summary>
internal sealed record CaptureInfo(byte[]? Image, string Note);

/// <summary>
/// Everything the shared UI needs from its host OS that isn't guard logic:
/// shell integration, startup, elevation, camera, tray art. One impl per
/// platform (WinUiHost / MacUiHost); features a host lacks are reported via
/// <see cref="Capabilities"/> and the UI disables them with a reason.
/// </summary>
internal interface IUiHost
{
    PlatformCapabilities Capabilities { get; }

    /// <summary>The OS asks for reduced motion (honored alongside the setting).</summary>
    bool OsPrefersReducedMotion { get; }

    bool IsElevated { get; }

    string VersionText { get; }

    /// <summary>Tray icon art for a guard state (PNG/ICO stream).</summary>
    Stream TrayIcon(GuardState state);

    /// <summary>App icon art for windows.</summary>
    Stream AppIcon();

    /// <summary>Screen point (pixels) the tray flyout should anchor near; null = OS default corner.</summary>
    (int X, int Y)? CursorPosition();

    void OpenFolder(string path);
    void RevealFile(string path);
    void OpenUrl(string url);

    UiStartupMode GetStartupMode();

    /// <summary>Apply a startup mode — may raise an elevation prompt. Returns null on success or an error.</summary>
    Task<string?> SetStartupModeAsync(UiStartupMode mode, Action<string> progress);

    bool ShortcutExists(UiShortcut which);
    void SetShortcut(UiShortcut which, bool enabled);

    /// <summary>Launch an elevated --takeover instance; null = started (caller then exits), else the error.</summary>
    string? StartElevatedInstance();

    string CapturesDir { get; }
    void TestCamera(Action<string> log);
    CaptureInfo LatestCapture(bool webcamEnabled);

    /// <summary>Called when the main window opens/closes (macOS shows the Dock icon only while open).</summary>
    void MainWindowVisibilityChanged(bool visible);
}
