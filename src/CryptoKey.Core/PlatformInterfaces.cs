using System.IO.Pipes;

namespace CryptoKey;

// Platform seams — one per OS capability Core logic touches. Hosts provide
// the impls (Win32/WinForms on Windows; CoreGraphics/IOKit/Keychain on macOS).

internal interface IPlatformPaths
{
    /// <summary>Config root: %APPDATA%\CryptoKey / ~/Library/Application Support/CryptoKey.</summary>
    string ConfigDir { get; }
}

internal interface IKeyProtector
{
    /// <summary>Seal a blob to this user+machine (DPAPI / Keychain).</summary>
    byte[] Protect(byte[] data, byte[] entropy);

    /// <summary>Unseal. Throws on failure — callers fail closed.</summary>
    byte[] Unprotect(byte[] data, byte[] entropy);
}

internal interface IUsbEnumerator
{
    List<UsbDisk> Enumerate();
}

internal static class UsbEnumeratorExtensions
{
    /// <summary>The enrolled device, if currently attached.</summary>
    public static UsbDisk? FindDisk(this IUsbEnumerator usb, string serial)
        => usb.Enumerate().FirstOrDefault(d =>
            string.Equals(d.SerialNumber, serial, StringComparison.OrdinalIgnoreCase));
}

/// <summary>Live presence watch for the enrolled key — events fire on the UI thread.</summary>
internal interface IKeyMonitor : IDisposable
{
    /// <summary>Raised when target presence flips; arg = now present.</summary>
    event Action<bool>? PresenceChanged;

    /// <summary>Raised after every check; arg = the disk, or null.</summary>
    event Action<UsbDisk?>? PresenceChecked;

    /// <summary>Raised when enumeration fails — for the activity log.</summary>
    event Action<string>? ErrorLogged;

    void SetPollInterval(int ms);

    /// <summary>Watch a different serial after re-enroll — also re-checks now.</summary>
    void SetTargetSerial(string serial);
}

/// <summary>Marshal work onto the pump the monitor locks/uphooks on.</summary>
internal interface IUiDispatcher
{
    /// <summary>Queue, don't block (BeginInvoke / Dispatcher.Post).</summary>
    void Post(Action work);

    /// <summary>Run synchronously on the UI thread and return the result (Invoke).</summary>
    T Send<T>(Func<T> work);
}

/// <summary>A live monitor plus the dispatcher that owns its thread.</summary>
internal sealed record KeyMonitorHandle(IKeyMonitor Monitor, IUiDispatcher Ui);

internal interface IKeyMonitorFactory
{
    KeyMonitorHandle Create(string targetSerial);
}

internal interface IIpcSecurity
{
    /// <summary>
    /// Create one server-side pipe instance. <paramref name="integrityLabeled"/>
    /// reports whether the OS-level integrity label was applied (Windows SACL);
    /// platforms whose pipes are already per-user return false harmlessly.
    /// </summary>
    NamedPipeServerStream CreatePipe(out bool integrityLabeled);

    /// <summary>True when this host is elevated such that a normal-integrity
    /// client can't reach the pipe without the integrity label.</summary>
    bool Elevated { get; }
}

internal interface ISingleInstance
{
    /// <summary>
    /// Claim a named instance lock; null means another holder owns it. With
    /// <paramref name="waitForRelease"/>, retries ~30s so a relaunch can take
    /// over the moment the old instance exits (takeover handoff).
    /// </summary>
    IDisposable? Acquire(string name, bool waitForRelease);

    /// <summary>Is the named lock currently held by a live process?</summary>
    bool IsHeld(string name);
}

/// <summary>The named stand-down channel a Supervisor signals and a Watchdog waits on.</summary>
internal interface IStopSignalFactory
{
    /// <summary>The watchdog's side — dispose to release.</summary>
    IStopSignalWaiter OpenWaiter();

    /// <summary>Clear a stale stand-down before spawning.</summary>
    void Reset();

    /// <summary>Raise the stand-down — the watchdog exits on its next beat.</summary>
    void Signal();
}

internal interface IStopSignalWaiter : IDisposable
{
    /// <summary>Block up to <paramref name="ms"/>; true when the signal is raised.</summary>
    bool Wait(int ms);
}

internal interface ILockPolicies
{
    void Apply(Action<string> log);
    void Restore(Action<string> log);
}

internal interface ICaptureService
{
    void Snap(string reason, Action<string>? log = null);
}

internal interface ISystemActions
{
    /// <summary>OS-level session lock — the fail-closed floor.</summary>
    void LockScreen();

    /// <summary>Milliseconds since the last user input.</summary>
    uint IdleMilliseconds();

    /// <summary>Pull input back to the user's desktop — no-op where locks self-release.</summary>
    void ReleaseInputDesktop();
}

internal interface IConfigBackup
{
    string? Read();
    void Write(string json);
    void Delete();
}

internal interface IKeyfileAttrs
{
    /// <summary>Hide the just-written keyfile (Hidden|System / leading dot is enough).</summary>
    void Hide(string path);
}

internal interface IAppLifetime
{
    /// <summary>End the app run-loop and exit the process.</summary>
    void Exit();
}

internal interface ILockSurfaceFactory
{
    /// <summary>
    /// <paramref name="securePreferred"/> asks for the stronger tier (private
    /// desktop / display capture); false asks for the overlay-class surface
    /// (the mid-flight fallback when the strong tier fails).
    /// </summary>
    ILockSurface Create(bool securePreferred, bool devMode);
}

internal interface IEnrollmentExtras
{
    /// <summary>After a successful enroll — shell shortcuts on Windows; LaunchAgent kickstart on Mac.</summary>
    void AfterEnroll();
}

internal interface IUserAlerts
{
    /// <summary>A modal warning for paths with no console reader (autostart launches).</summary>
    void Warn(string message);
}
