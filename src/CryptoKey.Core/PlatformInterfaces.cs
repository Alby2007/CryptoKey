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

/// <summary>Audible cues — synthesized WAVs on Windows; silent where unimplemented.</summary>
internal interface ICues
{
    /// <summary>Low thunk — the lock dropping into place.</summary>
    void Lock();

    /// <summary>Short two-note chime — session unlocked.</summary>
    void Unlock();

    /// <summary>Harsh triple blip — tamper/flap-storm events.</summary>
    void Alarm();
}

/// <summary>
/// The vault mount engine — Dokany on Windows; null impl elsewhere.
/// <see cref="DriverPresent"/> must be honest: a missing kernel driver
/// means mounts can never succeed, and the UI reports that rather than
/// pretending.
/// </summary>
internal interface IVaultMounter
{
    /// <summary>True when the mount engine's driver/dependency is installed.</summary>
    bool DriverPresent { get; }

    /// <summary>User-facing hint when <see cref="DriverPresent"/> is false.</summary>
    string? DriverHint { get; }

    /// <summary>Mount a prepared volume at a drive letter; null + error on failure.</summary>
    IVaultMount? Mount(VaultVolume volume, string mountPoint, out string? error);
}

/// <summary>A live mount — Dispose force-dismounts (open handles see I/O errors).</summary>
internal interface IVaultMount : IDisposable
{
    /// <summary>The mounted drive root, e.g. "V:\".</summary>
    string MountPoint { get; }

    /// <summary>Raised when the filesystem detaches on its own (external unmount, driver loss).</summary>
    event Action? Detached;
}

/// <summary>
/// TPM-bound pepper protector for the vault's machine binding. Implementations
/// wrap/unwrap a 32B pepper under a hardware-anchored key so a copied image +
/// cloned keyfile can't open on another machine. All failures are soft —
/// null/false, never throw — so TPM absence downgrades the vault to
/// phrase-recovery, never to a crash.
/// </summary>
internal interface IVaultTpm
{
    /// <summary>The TPM provider answers. Doesn't imply a pepper key exists.</summary>
    bool Available { get; }

    /// <summary>
    /// Wrap <paramref name="pepper"/> (32B) under the persistent TPM key,
    /// creating the key if needed. Returns the blob for the header's
    /// <c>tpmPepperBlob</c> field; null when the TPM refuses.
    /// </summary>
    byte[]? WrapPepper(byte[] pepper);

    /// <summary>Unwrap a stored pepper blob; null when the TPM refuses/absent.</summary>
    byte[]? UnwrapPepper(byte[] blob);

    /// <summary>Delete the persisted pepper key — best-effort, never throws.</summary>
    void DeleteKey();
}
