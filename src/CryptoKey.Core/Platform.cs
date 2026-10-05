namespace CryptoKey;

/// <summary>
/// The host's platform implementation bundle — every OS-specific capability
/// Core logic needs. Hosts build one and hand it to <see cref="Platform.Init"/>
/// before touching ConfigStore/GuardService/etc. Tests install a bundle of
/// temp-dir/null impls.
/// </summary>
internal sealed class PlatformServices
{
    /// <summary>Config directory root — CRYPTOKEY_CONFIG_ROOT still overrides it.</summary>
    public required IPlatformPaths Paths { get; init; }

    /// <summary>Keyfile envelope seal — DPAPI on Windows, Keychain on macOS.</summary>
    public required IKeyProtector Protector { get; init; }

    /// <summary>USB device enumeration (WMI / IOKit).</summary>
    public required IUsbEnumerator Usb { get; init; }

    /// <summary>Creates the live presence monitor (and its UI dispatcher).</summary>
    public required IKeyMonitorFactory KeyMonitors { get; init; }

    /// <summary>Server-side pipe security for the control channel.</summary>
    public required IIpcSecurity Ipc { get; init; }

    /// <summary>Named single-instance primitive (Mutex / flock).</summary>
    public required ISingleInstance SingleInstance { get; init; }

    /// <summary>Named stand-down channel between Supervisor and Watchdog.</summary>
    public required IStopSignalFactory StopSignals { get; init; }

    /// <summary>OS lockdown affordances while locked — no-op where the OS has none.</summary>
    public required ILockPolicies LockPolicies { get; init; }

    /// <summary>Webcam tamper snapshot — no-op where unsupported.</summary>
    public required ICaptureService Capture { get; init; }

    /// <summary>OS actions: workstation lock, idle meter, input-desktop release.</summary>
    public required ISystemActions SystemActions { get; init; }

    /// <summary>Third config copy on a different kill surface (registry / plist file).</summary>
    public required IConfigBackup ConfigBackup { get; init; }

    /// <summary>Hides the keyfile from casual browsing (attrib / dotfile).</summary>
    public required IKeyfileAttrs KeyfileAttrs { get; init; }

    /// <summary>Process exit for the running app host.</summary>
    public required IAppLifetime AppLifetime { get; init; }

    /// <summary>Lock surface construction — secure-tier and overlay-class.</summary>
    public required ILockSurfaceFactory Surfaces { get; init; }

    /// <summary>Post-enroll extras (shell shortcuts) — no-op where N/A.</summary>
    public required IEnrollmentExtras EnrollmentExtras { get; init; }

    /// <summary>Modal warning presenter for headless/config-failure paths.</summary>
    public required IUserAlerts UserAlerts { get; init; }

    /// <summary>Audible lock/unlock/alarm cues — null impl where unsupported.</summary>
    public required ICues Cues { get; init; }
}

/// <summary>
/// Ambient holder for <see cref="PlatformServices"/> — statics like
/// ConfigStore and KeyVerifier read it instead of taking dependencies.
/// Initialized by the host as the very first statement of Main; tests
/// install a temp bundle in their init fixture.
/// </summary>
internal static class Platform
{
    private static PlatformServices? _services;

    public static PlatformServices Services
        => _services ?? throw new InvalidOperationException(
            "Platform services not initialized — call Platform.Init first.");

    public static void Init(PlatformServices services) => _services = services;
}
