namespace CryptoKey.Ui;

/// <summary>Detached settings view for the UI — never the live config.</summary>
internal sealed record SettingsView(GuardSettings Guard, string DeviceSerial, int RotationCount);

/// <summary>
/// The UI's only door into the guard engine.
///
/// Threading contract: on Windows the engine (GuardService, key monitor,
/// classic lock + hooks) owns a dedicated WinForms thread and the UI runs on
/// Avalonia's thread; on macOS both share one thread. Either way:
/// <list type="bullet">
/// <item>engine events are re-posted onto the UI thread;</item>
/// <item>every command and config mutation executes ON the engine thread
/// (via the engine's own dispatcher) and completes as a Task, so a slow
/// operation (vault create, PBKDF2, WMI) never freezes the UI;</item>
/// <item>the UI reads only immutable snapshots (<see cref="Snapshot"/>,
/// <see cref="Settings"/>) — it never touches the live KeyConfig.</item>
/// </list>
/// </summary>
internal sealed class GuardClient : IDisposable
{
    private readonly GuardService _svc;
    private readonly KeyConfig _config;
    private readonly IUiDispatcher _engine;
    private readonly Action<Action> _toUi;
    private readonly RingBuffer<string> _activity = new(500);

    /// <summary>Must be constructed on the engine thread (it snapshots engine state).</summary>
    public GuardClient(GuardService service, KeyConfig config, bool devMode, Action<Action> postToUi)
    {
        _svc = service;
        _config = config;
        _engine = service.UiDispatcher;
        _toUi = postToUi;
        DevMode = devMode;
        Snapshot = service.Snapshot();
        Settings = Capture();
        foreach (string line in service.RecentActivity)
            _activity.Push(line);
        service.StateChanged += OnEngineState;
        service.ActivityLogged += OnEngineActivity;
        service.Notification += OnEngineNotification;
    }

    public bool DevMode { get; }

    /// <summary>Latest status (UI thread).</summary>
    public StatusSnapshot Snapshot { get; private set; }

    /// <summary>Latest settings view (UI thread).</summary>
    public SettingsView Settings { get; private set; }

    /// <summary>Activity lines oldest-first: backfill + everything since (UI thread).</summary>
    public IReadOnlyList<string> Activity => _activity;

    public event Action<StatusSnapshot>? StateChanged;
    public event Action<string>? ActivityLogged;
    public event Action<string, string>? Notification;
    public event Action<SettingsView>? SettingsChanged;

    private SettingsView Capture() => new(_config.Guard.Clone(), _config.DeviceSerial, _config.RotationCount);

    // ---------------------------------------------------------- engine → UI

    private void OnEngineState(StatusSnapshot snap)
    {
        SettingsView settings = Capture(); // rotations bump the generation
        _toUi(() =>
        {
            Snapshot = snap;
            StateChanged?.Invoke(snap);
            PublishSettings(settings);
        });
    }

    private void OnEngineActivity(string line) => _toUi(() =>
    {
        _activity.Push(line);
        ActivityLogged?.Invoke(line);
    });

    private void OnEngineNotification(string title, string body)
        => _toUi(() => Notification?.Invoke(title, body));

    private void PublishSettings(SettingsView next)
    {
        if (SettingsEqual(Settings, next))
            return;
        Settings = next;
        SettingsChanged?.Invoke(next);
    }

    private static bool SettingsEqual(SettingsView a, SettingsView b)
        => a.DeviceSerial == b.DeviceSerial && a.RotationCount == b.RotationCount
           && a.Guard.ValuesEqual(b.Guard);

    // ---------------------------------------------------------- UI → engine

    /// <summary>Run <paramref name="work"/> on the engine thread; result back as a Task.</summary>
    public Task<T> Query<T>(Func<GuardService, KeyConfig, T> work)
        => Task.Run(() => _engine.Send(() =>
        {
            T result = work(_svc, _config);
            SettingsView settings = Capture();
            _toUi(() => PublishSettings(settings));
            return result;
        }));

    public Task Run(Action<GuardService, KeyConfig> work)
        => Query((s, c) => { work(s, c); return true; });

    /// <summary>
    /// The one config-write path: mutate on the engine thread, persist,
    /// flag the attestation re-bind, and apply live side effects (poll rate,
    /// motion, vault enablement). Returns null on success or the error.
    /// </summary>
    public Task<string?> UpdateSettings(Action<GuardSettings> mutate)
        => Query<string?>((svc, cfg) =>
        {
            GuardSettings before = cfg.Guard.Clone();
            mutate(cfg.Guard);
            try
            {
                ConfigStore.Save(cfg);
            }
            catch (Exception ex)
            {
                return $"Save failed: {ex.Message}";
            }
            // Covered-field saves trip the keyfile's config attestation —
            // flag it so the next verify re-binds quietly instead of
            // announcing a tamper event we caused ourselves.
            svc.MarkConfigDirty();
            GuardSettings after = cfg.Guard;
            if (after.PollIntervalMs != before.PollIntervalMs)
                svc.ApplyPollInterval(after.PollIntervalMs);
            if (after.Animations != before.Animations)
                svc.ApplyMotion(after.Animations);
            if (after.VaultEnabled != before.VaultEnabled)
                svc.Vault.ReloadConfig();
            return null;
        });

    public void Lock() => _ = Run((s, _) => s.RequestLock());

    public Task<string?> Pause(int minutes)
        => Query<string?>((s, _) => s.Pause(minutes, out string err) ? null : err);

    public void Resume() => _ = Run((s, _) => s.Resume());

    /// <summary>Quit is refused while locked (quitting = unlocking).</summary>
    public Task<bool> RequestQuit() => Query((s, _) => s.RequestQuit());

    /// <summary>Same dispatch table the IPC pipe and CLI use.</summary>
    public Task<string> Dispatch(string command) => Query((s, _) => s.DispatchCommand(command));

    public void Log(string message) => _engine.Post(() => _svc.Log(message));

    /// <summary>Unconditional process exit through the host lifetime (elevated relaunch).</summary>
    public void Exit() => _engine.Post(() => Platform.Services.AppLifetime.Exit());

    public void Dispose()
    {
        _svc.StateChanged -= OnEngineState;
        _svc.ActivityLogged -= OnEngineActivity;
        _svc.Notification -= OnEngineNotification;
    }
}
