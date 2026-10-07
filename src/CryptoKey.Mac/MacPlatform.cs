using System.IO.Pipes;

namespace CryptoKey;

/// <summary>
/// The macOS platform bundle — every Core seam bound to its Darwin/
/// CoreGraphics/Security implementation. Registered by Program.Main before
/// anything touches Core. Phase 2 is the headless tier: the lock surface is
/// display capture + event tap (no window UI), and alerts go through
/// osascript when a user session is around.
/// </summary>
internal static class MacPlatform
{
    /// <summary>Headless bundle — own pump, no lock windows.</summary>
    public static PlatformServices Services
    {
        get
        {
            var pump = new MacPump();
            return Build(pump, pump, null);
        }
    }

    /// <summary>Avalonia bundle — the Dispatcher is the pump, windows exist.</summary>
    public static PlatformServices UiServices(
        AvaloniaUiDispatcher ui, LockWindowCtl lockUi)
        => Build(ui, ui, lockUi);

    /// <summary>Headless bundle on a caller-owned pump.</summary>
    public static PlatformServices Headless(MacPump pump)
        => Build(pump, pump, null);

    private static PlatformServices Build(
        IUiDispatcher ui, IAppLifetime lifetime, LockWindowCtl? lockUi)
        => new PlatformServices
        {
            Paths = new MacPaths(),
            Protector = new KeychainProtector(),
            Usb = new MacUsbEnumerator(),
            KeyMonitors = new MacKeyMonitorFactory(ui),
            Ipc = new MacIpcSecurity(),
            SingleInstance = new FlockSingleInstance(),
            StopSignals = new MacStopSignals(),
            LockPolicies = new NullLockPolicies(),
            Capture = new NullCaptureService(),
            SystemActions = new MacSystemActions(),
            ConfigBackup = new FileConfigBackup(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "Library", "Preferences", "CryptoKey", "config-backup.json")),
            KeyfileAttrs = new NoopKeyfileAttrs(), // ".cryptokey" is a dotfile already
            AppLifetime = lifetime,
            Surfaces = new MacLockSurfaceFactory(lockUi),
            EnrollmentExtras = new MacEnrollmentExtras(),
            UserAlerts = new MacUserAlerts(),
            // afplay /System/Library/Sounds/*.aiff is the natural impl —
            // silent until the Mac host picks it up.
            Cues = new NullCues(),
            // macFUSE is the eventual mount engine — vault stays image-only for now.
            VaultMounts = new NullVaultMounter(),
            VaultTpm = NullVaultTpm.Shared,
            Capabilities = Capabilities,
        };

    /// <summary>
    /// What the macOS host can actually do — the dashboard gates on this:
    /// capture+tap IS the strong lock tier (no private-desktop split), and
    /// vault mounting, webcam captures, lock policies and elevation are
    /// Windows-only for now.
    /// </summary>
    public static PlatformCapabilities Capabilities { get; } = new("macOS",
        Vault: false, Tpm: false, Webcam: false, PrivateDesktop: false,
        LockPolicies: false, Elevation: false, Shortcuts: false,
        StartupAtLogin: true);
}

internal sealed class MacPaths : IPlatformPaths
{
    public string ConfigDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        "Library", "Application Support", "CryptoKey");
}

/// <summary>
/// The headless pump — the UI-thread stand-in on macOS until Avalonia lands.
/// A BlockingCollection<Action> serviced on the main thread gives Core's
/// marshaling calls somewhere real to run: IPC dispatch, rotation logging,
/// idle-lock ticks all land here, and AppLifetime.Exit ends the pump.
/// </summary>
internal sealed class MacPump : IUiDispatcher, IAppLifetime
{
    private readonly System.Collections.Concurrent.BlockingCollection<Action> _queue = new();
    private volatile bool _exited;

    /// <summary>Run the pump on the calling thread until Exit is posted.</summary>
    public void Run()
    {
        foreach (Action work in _queue.GetConsumingEnumerable())
        {
            try { work(); }
            catch (Exception) { /* a bad callback must not kill the pump */ }
        }
    }

    public void Post(Action work)
    {
        if (_exited)
            return;
        try { _queue.Add(work); }
        catch (InvalidOperationException) { /* completed — shutting down */ }
    }

    public T Send<T>(Func<T> work)
    {
        // Callers run OFF the pump (IPC server thread). Marshal in, block out.
        if (_exited)
            throw new InvalidOperationException("pump is stopped");
        var done = new ManualResetEventSlim();
        T? result = default;
        Exception? error = null;
        Post(() =>
        {
            try { result = work(); }
            catch (Exception ex) { error = ex; }
            finally { done.Set(); }
        });
        // Bounded wait — if the pump dies after the Post lands, an unbounded
        // Wait would wedge the IPC thread forever.
        if (!done.Wait(TimeSpan.FromSeconds(15)))
            throw new TimeoutException("pump did not run the work item");
        if (error != null)
            throw error;
        return result!;
    }

    public void Exit()
    {
        _exited = true;
        _queue.CompleteAdding();
    }
}

/// <summary>
/// Poll-based presence monitor — macOS has no WM_DEVICECHANGE; a dedicated
/// 1s thread watches the enumerator and raises through the dispatcher so
/// handlers keep their pump-thread affinity.
/// </summary>
internal sealed class MacKeyMonitor : IKeyMonitor
{
    public event Action<bool>? PresenceChanged;
    public event Action<UsbDisk?>? PresenceChecked;
    public event Action<string>? ErrorLogged;

    private const int MaxConsecutiveErrors = 3;

    private readonly IUiDispatcher _ui;
    private readonly Thread _thread;
    private readonly ManualResetEventSlim _wake = new();
    private volatile bool _dead;
    private string _targetSerial;
    private bool _lastPresent;
    private int _consecutiveErrors;
    private int _pollMs = 1000;

    public MacKeyMonitor(string targetSerial, IUiDispatcher ui)
    {
        _targetSerial = targetSerial;
        _ui = ui;
        try
        {
            _lastPresent = Platform.Services.Usb.FindDisk(_targetSerial) != null;
        }
        catch (Exception)
        {
            _lastPresent = false; // can't prove the key is there — fail closed
        }
        _thread = new Thread(Loop) { IsBackground = true, Name = "ck-keymon" };
        _thread.Start();
    }

    public void SetPollInterval(int ms)
        => _pollMs = Math.Clamp(ms, 250, 10_000); // match Settings slider

    public void SetTargetSerial(string serial)
    {
        _targetSerial = serial;
        _wake.Set(); // re-check now, don't wait out the interval
    }

    private void Loop()
    {
        while (!_dead)
        {
            _wake.Wait(_pollMs);
            _wake.Reset();
            if (_dead)
                break;
            UsbDisk? disk;
            try
            {
                disk = Platform.Services.Usb.FindDisk(_targetSerial);
                _consecutiveErrors = 0;
            }
            catch (Exception ex)
            {
                // Same rule as the Windows monitor: tolerate a few hiccups,
                // then fail closed so a dead enumerator can't leave us unlocked.
                _consecutiveErrors++;
                int errs = _consecutiveErrors;
                _ui.Post(() => ErrorLogged?.Invoke(
                    $"USB enumeration error #{errs}: {ex.Message}"));
                disk = errs < MaxConsecutiveErrors ? _pendingDisk : null;
            }
            _pendingDisk = disk;
            _ui.Post(() => ApplyCheck(disk));
        }
    }

    private UsbDisk? _pendingDisk; // last-seen disk, held through the error window

    // Runs on the pump thread with the enumeration result.
    private void ApplyCheck(UsbDisk? disk)
    {
        bool present = disk != null;
        if (present != _lastPresent)
        {
            _lastPresent = present;
            PresenceChanged?.Invoke(present);
        }
        PresenceChecked?.Invoke(disk);
    }

    public void Dispose()
    {
        _dead = true;
        _wake.Set();
        // _wake is deliberately NOT disposed: the loop can sit between
        // Reset() and the next Wait() while Dispose runs, and a disposed
        // Wait would throw on the monitor thread — an unhandled crash
        // during shutdown. Abandoned MRESes cost nothing.
    }
}

internal sealed class MacKeyMonitorFactory : IKeyMonitorFactory
{
    private readonly IUiDispatcher _ui;
    public MacKeyMonitorFactory(IUiDispatcher ui) => _ui = ui;

    public KeyMonitorHandle Create(string targetSerial)
        => new(new MacKeyMonitor(targetSerial, _ui), _ui);
}

/// <summary>
/// .NET maps NamedPipeServerStream onto a unix socket under the per-user
/// $TMPDIR on macOS — already private to the session, no ACL work needed.
/// </summary>
internal sealed class MacIpcSecurity : IIpcSecurity
{
    public bool Elevated => false;

    public NamedPipeServerStream CreatePipe(out bool integrityLabeled)
    {
        integrityLabeled = false;
        return new NamedPipeServerStream(IpcServer.PipeName,
            PipeDirection.InOut,
            NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
    }

    /// <summary>Unix sockets don't expose first-instance semantics; the
    /// anchor is a normal held instance that keeps the socket path owned.</summary>
    public NamedPipeServerStream CreateAnchorPipe()
        => new(IpcServer.PipeName, PipeDirection.InOut,
            NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous);

    /// <summary>The socket lives under the per-user $TMPDIR — no spoofable
    /// peer identity to check at the client.</summary>
    public bool VerifyServerIsOurs(NamedPipeClientStream pipe) => true;
}

/// <summary>
/// flock() single-instance — released automatically on process death, which
/// is exactly the watchdog semantics the Windows mutex version relies on.
/// </summary>
internal sealed class FlockSingleInstance : ISingleInstance
{
    private const int TakeoverWaitSeconds = 30;

    public IDisposable? Acquire(string name, bool waitForRelease)
    {
        var deadline = DateTime.UtcNow.AddSeconds(TakeoverWaitSeconds);
        do
        {
            int fd = MacInterop.open(LockPath(name),
                MacInterop.O_WRONLY | MacInterop.O_CREAT | MacInterop.O_CLOEXEC, 0x180) /* 0600 */;
            if (fd >= 0 && MacInterop.flock(fd, MacInterop.LOCK_EX | MacInterop.LOCK_NB) == 0)
                return new Handle(fd);
            if (fd >= 0)
                MacInterop.close(fd);
            if (waitForRelease)
                Thread.Sleep(250);
        }
        while (waitForRelease && DateTime.UtcNow < deadline);
        return null;
    }

    public bool IsHeld(string name)
    {
        int fd = MacInterop.open(LockPath(name),
            MacInterop.O_WRONLY | MacInterop.O_CREAT | MacInterop.O_CLOEXEC, 0x180) /* 0600 */;
        if (fd < 0)
            return false;
        bool held = MacInterop.flock(fd, MacInterop.LOCK_EX | MacInterop.LOCK_NB) != 0;
        MacInterop.close(fd);
        return held;
    }

    private static string LockPath(string name)
        => Path.Combine(ConfigStore.ConfigDir, name + ".lock");

    private sealed class Handle : IDisposable
    {
        private readonly int _fd;
        public Handle(int fd) => _fd = fd;
        public void Dispose()
        {
            MacInterop.flock(_fd, 8 /* LOCK_UN */);
            MacInterop.close(_fd);
        }
    }
}

/// <summary>
/// Stand-down file in the config dir: Signal creates it, Reset deletes it,
/// the watchdog's Wait polls for it. Survives reboot is fine — the watchdog
/// arms it fresh on every spawn.
/// </summary>
internal sealed class MacStopSignals : IStopSignalFactory
{
    private static string Path_ =>
        Path.Combine(ConfigStore.ConfigDir, "watchdog.stop");

    public IStopSignalWaiter OpenWaiter() => new Waiter(Path_);
    public void Reset()
    {
        try { File.Delete(Path_); } catch { }
    }
    public void Signal()
    {
        try
        {
            Directory.CreateDirectory(ConfigStore.ConfigDir);
            File.WriteAllText(Path_, "stop\n");
        }
        catch { }
    }

    private sealed class Waiter : IStopSignalWaiter
    {
        private readonly string _path;
        public Waiter(string path) => _path = path;
        public bool Wait(int ms)
        {
            var deadline = DateTime.UtcNow.AddMilliseconds(ms);
            while (DateTime.UtcNow < deadline)
            {
                if (File.Exists(_path))
                    return true;
                Thread.Sleep(50);
            }
            return File.Exists(_path);
        }
        public void Dispose() { }
    }
}

internal sealed class MacSystemActions : ISystemActions
{
    /// <summary>Real OS lock — CGSession -suspend; pmset is the fallback.</summary>
    public void LockScreen()
    {
        const string cgSession = "/System/Library/CoreServices/Menu Extras/" +
            "User.menu/Contents/Resources/CGSession";
        try
        {
            if (File.Exists(cgSession))
            {
                System.Diagnostics.Process.Start(cgSession, "-suspend");
                return;
            }
            // Absolute path — launchd's PATH is minimal.
            System.Diagnostics.Process.Start("/usr/bin/pmset", "displaysleepnow");
        }
        catch (Exception) { }
    }

    public uint IdleMilliseconds()
    {
        double secs = MacInterop.CGEventSourceSecondsSinceLastEventType(
            MacInterop.HidSystemState, MacInterop.AnyInputEvent);
        return (uint)Math.Min(secs * 1000.0, uint.MaxValue);
    }

    /// <summary>
    /// macOS locks self-release on process death — capture and event taps
    /// are per-process resources. Releasing everything here is still right
    /// for a wedged-but-alive guard.
    /// </summary>
    public void ReleaseInputDesktop()
    {
        try { MacInterop.CGReleaseAllDisplays(); }
        catch (Exception) { }
    }
}

internal sealed class MacLockSurfaceFactory : ILockSurfaceFactory
{
    private readonly LockWindowCtl? _ui;

    public MacLockSurfaceFactory(LockWindowCtl? ui) => _ui = ui;

    /// <summary>
    /// One surface, both tiers: capture+tap IS the strong tier on macOS;
    /// the overlay distinction is a Windows artifact. securePreferred only
    /// sets which tier the surface claims to be, so GuardService's
    /// EnsureSurfaceMode has nothing to rebuild.
    /// </summary>
    public ILockSurface Create(bool securePreferred, bool devMode)
        => new MacLockSurface(devMode, _ui, securePreferred);
}

/// <summary>Post-enroll: a freshly enrolled guard should start immediately.</summary>
internal sealed class MacEnrollmentExtras : IEnrollmentExtras
{
    public void AfterEnroll() => MacInstall.KickstartIfInstalled();
}

/// <summary>Headless alert: osascript dialog if a UI session is up, else console.</summary>
internal sealed class MacUserAlerts : IUserAlerts
{
    public void Warn(string message)
    {
        try
        {
            // Backslash first — escaping quotes before backslashes would
            // double-escape and a trailing \ would still eat the close quote.
            string esc = message.Replace("\\", "\\\\").Replace("\"", "\\\"");
            var psi = new System.Diagnostics.ProcessStartInfo("/usr/bin/osascript")
            { UseShellExecute = false };
            psi.ArgumentList.Add("-e");
            psi.ArgumentList.Add($"display dialog \"{esc}\" with title \"CryptoKey\" " +
                "buttons {\"OK\"} default button 1 with icon stop");
            System.Diagnostics.Process.Start(psi);
        }
        catch (Exception) { }
    }
}
