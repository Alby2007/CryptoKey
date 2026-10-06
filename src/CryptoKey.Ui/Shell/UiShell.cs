using Avalonia;
using Avalonia.Controls;

namespace CryptoKey.Ui;

/// <summary>
/// The running app's front end: tray icon + menu, tray flyout, the
/// (lazily created) dashboard window, the re-enroll wizard, and branded
/// notifications. One per guard; lives on the UI thread.
/// </summary>
internal sealed class UiShell : IDisposable
{
    private static readonly int[] PauseChoices = { 5, 15, 60 };

    private readonly GuardClient _client;
    private readonly IUiHost _host;
    private readonly TrayIcon _tray;
    private readonly NativeMenuItem _statusItem;
    private readonly NativeMenuItem _keyItem;
    private readonly NativeMenuItem _lockItem;
    private readonly NativeMenuItem _pauseItem;
    private readonly NativeMenuItem _resumeItem;
    private readonly NativeMenuItem _quitItem;
    private readonly NotificationCenter _notes;
    private MainWindow? _window;
    private TrayFlyout? _flyout;
    private OnboardingWindow? _wizard;
    private GuardState? _iconState;

    public UiShell(GuardClient client, IUiHost host)
    {
        _client = client;
        _host = host;
        bool mac = host.Capabilities.PlatformName == "macOS";
        _notes = new NotificationCenter(anchorTop: mac);
        Motion.Configure(client.Settings.Guard.Animations, !host.OsPrefersReducedMotion);

        _statusItem = new NativeMenuItem("CryptoKey") { IsEnabled = false };
        _keyItem = new NativeMenuItem("") { IsEnabled = false };
        var open = Item("Open CryptoKey", () => OpenWindow(Route.Home));
        var quick = Item("Quick panel…", ShowFlyout);
        _lockItem = Item("Lock now", () => _client.Lock());
        _pauseItem = new NativeMenuItem("Pause auto-lock") { Menu = new NativeMenu() };
        foreach (int mins in PauseChoices)
        {
            int m = mins;
            _pauseItem.Menu.Items.Add(Item($"{m} minutes", async () =>
            {
                string? err = await _client.Pause(m);
                if (err != null)
                    Notify("CryptoKey", err, Tone.Warn, IconData.Warning);
            }));
        }
        _resumeItem = Item("Resume", () => _client.Resume());
        var settings = Item("Settings…", () => OpenWindow(Route.General));
        _quitItem = Item("Quit CryptoKey", Quit);

        var menu = new NativeMenu();
        foreach (NativeMenuItemBase it in new NativeMenuItemBase[]
                 {
                     _statusItem, _keyItem, new NativeMenuItemSeparator(), open, quick,
                     new NativeMenuItemSeparator(), _lockItem, _pauseItem, _resumeItem, settings,
                     new NativeMenuItemSeparator(), _quitItem,
                 })
            menu.Items.Add(it);

        _tray = new TrayIcon { Menu = menu, ToolTipText = "CryptoKey" };
        // Left-click opens the flyout (Windows/Linux; macOS always shows the menu).
        _tray.Clicked += (_, _) => ToggleFlyout();
        TrayIcon.SetIcons(Application.Current!, new TrayIcons { _tray });

        _client.StateChanged += OnState;
        _client.Notification += (t, b) =>
        {
            if (_client.Settings.Guard.BalloonTips)
                Notify(t, b, Tone.Signal, IconData.Bell);
        };
        _client.SettingsChanged += s => Motion.SetSetting(s.Guard.Animations);
        Apply(_client.Snapshot, announce: false);
    }

    private static NativeMenuItem Item(string header, Action onClick)
    {
        var item = new NativeMenuItem(header);
        item.Click += (_, _) => onClick();
        return item;
    }

    private void OnState(StatusSnapshot s) => Apply(s, announce: true);

    private void Apply(StatusSnapshot s, bool announce)
    {
        _statusItem.Header = s.State == GuardState.Paused
            ? $"CryptoKey — PAUSED until {s.PausedUntil:HH:mm}"
            : $"CryptoKey — {s.State.ToString().ToUpperInvariant()}";
        _keyItem.Header = s.KeyPresent
            ? $"Key: {s.Model} — present"
            : $"Key: absent ({_client.Settings.DeviceSerial})";
        _lockItem.IsEnabled = s.State != GuardState.Locked;
        _pauseItem.IsEnabled = s.State != GuardState.Locked; // can extend a pause
        _resumeItem.IsEnabled = s.State == GuardState.Paused;
        _quitItem.IsEnabled = s.State != GuardState.Locked;

        if (s.State == _iconState)
            return;
        GuardState? prev = _iconState;
        _iconState = s.State;
        try { _tray.Icon = new WindowIcon(_host.TrayIcon(s.State)); }
        catch (Exception) { }
        _tray.ToolTipText = s.State switch
        {
            GuardState.Locked => "CryptoKey — LOCKED",
            GuardState.Paused => $"CryptoKey — paused until {s.PausedUntil:HH:mm}",
            _ => "CryptoKey — armed",
        };

        if (s.State == GuardState.Locked)
        {
            // Nothing of the dashboard stays reachable over a lock; sensitive
            // fields clear as pages detach.
            _flyout?.Hide();
            _window?.Hide();
            _wizard?.Close();
        }

        if (!announce || prev == null || !_client.Settings.Guard.BalloonTips)
            return;
        switch (s.State)
        {
            case GuardState.Locked:
                Notify("Locked", "Key absent or unverified.", Tone.Danger, IconData.Lock);
                break;
            case GuardState.Unlocked:
                Notify("Unlocked", "Welcome back — protection is armed.", Tone.Ok, IconData.Unlock);
                break;
            case GuardState.Paused:
                Notify("Auto-lock paused", $"Resumes at {s.PausedUntil:HH:mm}.", Tone.Warn, IconData.Pause);
                break;
        }
    }

    public void Notify(string title, string body, Tone tone, string icon)
    {
        try { _notes.Show(title, body, tone, icon); }
        catch (Exception) { }
    }

    /// <summary>Show the dashboard (created on first use) on the given page.</summary>
    public void OpenWindow(Route route = Route.Home)
    {
        if (_client.Snapshot.State == GuardState.Locked)
            return;
        _flyout?.Hide();
        if (_window == null)
        {
            _window = new MainWindow(_client, _host, OpenOnboarding);
            _window.Closed += (_, _) =>
            {
                _window = null;
                _host.MainWindowVisibilityChanged(false);
            };
            _window.PropertyChanged += (_, e) =>
            {
                if (e.Property == Visual.IsVisibleProperty)
                    _host.MainWindowVisibilityChanged(_window?.IsVisible == true);
            };
        }
        _window.Navigate(route);
        _window.Show();
        if (_window.WindowState == WindowState.Minimized)
            _window.WindowState = WindowState.Normal;
        _window.Activate();
        _host.MainWindowVisibilityChanged(true);
    }

    public void ShowFlyout()
    {
        if (_client.Snapshot.State == GuardState.Locked)
            return;
        _flyout ??= new TrayFlyout(_client, _host, OpenWindow, Quit);
        _flyout.ShowNear();
    }

    private void ToggleFlyout()
    {
        if (_flyout?.IsVisible == true)
            _flyout.Hide();
        else
            ShowFlyout();
    }

    /// <summary>In-app re-enroll: commit + config reload run atomically on the engine thread.</summary>
    public void OpenOnboarding()
    {
        if (_wizard != null)
        {
            _wizard.Activate();
            return;
        }
        _wizard = new OnboardingWindow(_host, firstRun: false, (flow, configure) =>
            _client.Query((svc, _) =>
            {
                EnrollResult r = flow.Commit(configure);
                if (r.Ok)
                    svc.ReloadConfig();
                return r;
            }));
        _wizard.Closed += (_, _) => _wizard = null;
        if (_window is { IsVisible: true })
            _wizard.Show(_window);
        else
            _wizard.Show();
    }

    private async void Quit()
    {
        if (!await _client.RequestQuit())
            Notify("Can't quit while locked", "Insert the key or enter the recovery phrase first.", Tone.Danger, IconData.Lock);
    }

    /// <summary>Close every window — the UI crash policy and shutdown both use this.</summary>
    public void CloseWindows()
    {
        try { _flyout?.Close(); } catch (Exception) { }
        try { _wizard?.Close(); } catch (Exception) { }
        try { _window?.Close(); } catch (Exception) { }
        _flyout = null;
        _window = null;
    }

    public void Dispose()
    {
        _client.StateChanged -= OnState;
        CloseWindows();
        _tray.IsVisible = false;
        _tray.Dispose();
    }
}
