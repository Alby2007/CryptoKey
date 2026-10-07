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
        // The session's death closes every authorized surface — an open
        // dashboard/flyout/wizard must not keep running its mutators after
        // sign-out or a dead refresh token. The auth window survives (it's
        // the way back in). May arrive on any thread — marshal to the UI.
        AuthService.Current.SessionEnded += () => UiRuntime.Post(() =>
        {
            _window?.Close();
            _flyout?.Hide();
            _wizard?.Close();
        });
        bool mac = host.Capabilities.PlatformName == "macOS";
        _notes = new NotificationCenter(anchorTop: mac);
        Motion.Configure(client.Settings.Guard.Animations, !host.OsPrefersReducedMotion);

        _statusItem = new NativeMenuItem("CryptoKey") { IsEnabled = false };
        _keyItem = new NativeMenuItem("") { IsEnabled = false };
        var open = Item("Open CryptoKey", () => OpenWindow(Route.Home));
        // The flyout is a Windows/Linux tray idiom — on macOS the native
        // menu IS the quick panel.
        var quick = mac ? null : Item("Quick panel…", ShowFlyout);
        _lockItem = Item("Lock now", () => _client.Lock()); // open — only makes the box safer
        _pauseItem = new NativeMenuItem("Pause auto-lock") { Menu = new NativeMenu() };
        foreach (int mins in PauseChoices)
        {
            int m = mins;
            _pauseItem.Menu.Items.Add(Item($"{m} minutes", () => EnsureAuth(async () =>
            {
                string? err = await _client.Pause(m);
                if (err != null)
                    Notify("CryptoKey", err, Tone.Warn, IconData.Warning);
            })));
        }
        _resumeItem = Item("Resume", () => EnsureAuth(() => _client.Resume()));
        var settings = Item("Settings…", () => OpenWindow(Route.General));
        _quitItem = Item("Quit CryptoKey", () => EnsureAuth(Quit));

        var menu = new NativeMenu();
        foreach (NativeMenuItemBase? it in new NativeMenuItemBase?[]
                 {
                     _statusItem, _keyItem, new NativeMenuItemSeparator(), open, quick,
                     new NativeMenuItemSeparator(), _lockItem, _pauseItem, _resumeItem, settings,
                     new NativeMenuItemSeparator(), _quitItem,
                 })
        {
            if (it != null)
                menu.Items.Add(it);
        }

        _tray = new TrayIcon { Menu = menu, ToolTipText = "CryptoKey" };
        // Left-click opens the flyout (Windows/Linux; macOS always shows the menu).
        if (!mac)
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
        // Unsigned while an account is possible: the native menu is a
        // masked surface like the flyout — no state text, no key identity,
        // and the tooltip can't say "armed" while auto-lock is disarmed.
        // Action items stay enabled — they prompt sign-in through
        // EnsureAuth. Truly unaccounted installs (no backend, no record)
        // keep the honest readout — nothing exists to sign into.
        var auth0 = AuthService.Current;
        bool gatedOut = !auth0.SessionLive && (auth0.Gating || auth0.Configured);
        _statusItem.Header = gatedOut
            ? "CryptoKey — sign in to manage"
            : s.State == GuardState.Paused
                ? $"CryptoKey — PAUSED until {s.PausedUntil:HH:mm}"
                : $"CryptoKey — {s.State.ToString().ToUpperInvariant()}";
        _keyItem.IsVisible = !gatedOut;
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
        _tray.ToolTipText = gatedOut ? "CryptoKey — sign in" : s.State switch
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

    /// <summary>
    /// True when this session may open the dashboard / run sensitive ops
    /// without re-authenticating: a live or offline-unlocked account
    /// session — or an install that never enrolled an account at all (the
    /// gate has nothing to check against there; pre-account behavior is
    /// preserved).
    /// </summary>
    private bool AccountGatePassed()
    {
        AuthService auth = AuthService.Current;
        return auth.Authorized || !auth.Gating;
    }

    /// <summary>
    /// Run <paramref name="then"/> once the account gate is satisfied —
    /// immediately when authorized, else behind the auth window. A closed
    /// window abandons the action; the guard itself never gates.
    /// </summary>
    public void EnsureAuth(Action then)
    {
        if (AccountGatePassed())
        {
            then();
            return;
        }
        ShowAuth(auth => { if (auth) then(); });
    }

    /// <summary>
    /// Show the auth window (sign-in by default; unenrolled installs get
    /// the create face). One instance at a time; <paramref name="done"/>
    /// reports whether the session is authorized afterward.
    /// </summary>
    public void ShowAuth(Action<bool> done, AuthMode? mode = null)
    {
        if (_authWin != null)
        {
            // A forced face (a recovery deep link mid-sign-in) still lands —
            // swap the open window's face rather than dropping the link.
            if (mode != null)
                _authWin.SwitchFace(mode.Value, _pendingDeepLink);
            _pendingDeepLink = null;
            _authWin.Activate();
            _pendingAuthDone += done;
            return;
        }
        _pendingAuthDone = done;
        AuthMode picked = mode ?? (_pendingDeepLink != null ? AuthMode.Reset
            : AuthService.Current.State == AuthGateState.Unenrolled
                ? AuthMode.Create : AuthMode.SignIn);
        var w = new AuthWindow(_host, picked,
            keyPresent: () => _client.Snapshot.KeyPresent,
            tokenHash: _pendingDeepLink);
        _pendingDeepLink = null;
        _authWin = w;
        w.Closed += (_, _) =>
        {
            _authWin = null;
            var cb = _pendingAuthDone;
            _pendingAuthDone = null;
            cb?.Invoke(w.Authenticated || AccountGatePassed());
        };
        w.Show();
    }

    private AuthWindow? _authWin;
    private Action<bool>? _pendingAuthDone;
    private string? _pendingDeepLink;

    /// <summary>
    /// A cryptokey:// deep link arrived (app launch or IPC forward) —
    /// recovery links open the reset face once a window can host it.
    /// </summary>
    public void OnDeepLink(string url)
    {
        if (url.StartsWith("cryptokey://recover", StringComparison.OrdinalIgnoreCase)
            && QueryParam(url, "token_hash") is { Length: > 0 } th
            && QueryParam(url, "type")?.Equals("recovery",
                StringComparison.OrdinalIgnoreCase) == true)
        {
            _pendingDeepLink = th;
            // A recovery link means "finish the reset" — surface the auth
            // window directly regardless of gate state (it may be the
            // reason the session isn't authorized).
            ShowAuth(_ => { }, AuthMode.Reset);
        }
        else if (url.StartsWith("cryptokey://", StringComparison.OrdinalIgnoreCase))
        {
            // Any other cryptokey:// landing (e.g. the confirm-email Site
            // URL redirect) just needs the gate surfaced — sign in if the
            // session isn't authorized, else the dashboard.
            if (AccountGatePassed())
                OpenWindow();
            else
                ShowAuth(_ => { }, AuthMode.SignIn);
        }
    }

    /// <summary>url?<k>=<v>&… — one pair; percent-decoded, null when absent.</summary>
    private static string? QueryParam(string url, string key)
    {
        int q = url.IndexOf('?');
        if (q < 0)
            return null;
        foreach (string pair in url[(q + 1)..].Split('&',
            StringSplitOptions.RemoveEmptyEntries))
        {
            string[] kv = pair.Split('=', 2);
            if (kv.Length == 2
                && kv[0].Equals(key, StringComparison.OrdinalIgnoreCase))
                return Uri.UnescapeDataString(kv[1]);
        }
        return null;
    }

    /// <summary>Show the dashboard (created on first use) on the given page.</summary>
    public void OpenWindow(Route route = Route.Home)
    {
        if (_client.Snapshot.State == GuardState.Locked)
            return;
        _flyout?.Hide();
        if (!AccountGatePassed())
        {
            ShowAuth(auth => { if (auth) OpenWindow(route); });
            return;
        }
        if (_window == null)
        {
            _window = new MainWindow(_client, _host, OpenOnboarding, ShowAuth);
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
        // Read-only surfaces stay open — the mutators inside (pause,
        // resume, quit, vault mount) wrap themselves in the auth gate.
        _flyout ??= new TrayFlyout(_client, _host, OpenWindow, Quit, EnsureAuth,
            m => ShowAuth(_ => { }, m));
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
