namespace CryptoKey;

/// <summary>
/// Owns the tray icon, the (lazily created) main window, and the icon cache —
/// shared by GUI mode (window opens immediately) and daemon `guard` mode
/// (window appears on demand).
/// </summary>
internal sealed class AppShell : IDisposable
{
    private readonly GuardService _service;
    private readonly KeyConfig _config;
    private readonly bool _devMode;
    private readonly TrayIcons _icons = new();
    private readonly TrayApp _tray;
    private MainWindow? _window;

    public AppShell(GuardService service, KeyConfig config, bool devMode)
    {
        _service = service;
        _config = config;
        _devMode = devMode;
        _tray = new TrayApp(service, config, _icons, OpenWindow);
    }

    /// <summary>Show the main window (creating it on first use) on the given tab.</summary>
    public void OpenWindow(int tab = 0)
    {
        if (_window is { IsDisposed: false })
        {
            _window.Show();
            _window.WindowState = FormWindowState.Normal;
            _window.Activate();
            _window.Navigate(tab);
            return;
        }
        _window = new MainWindow(_service, _config, _icons, _devMode);
        _window.Navigate(tab);
        _window.FormClosed += (_, _) => _window = null;
        _window.Show();
    }

    public void Dispose()
    {
        _window?.Dispose();
        _tray.Dispose();
        _icons.Dispose();
    }
}
