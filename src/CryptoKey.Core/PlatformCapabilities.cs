namespace CryptoKey;

/// <summary>
/// What this host can actually do — the UI gates features on it instead of
/// hiding them, so both platforms share one information architecture and a
/// missing feature explains itself ("Not available on macOS").
/// </summary>
internal sealed record PlatformCapabilities(
    string PlatformName,
    bool Vault,
    bool Tpm,
    bool Webcam,
    bool PrivateDesktop,
    bool LockPolicies,
    bool Elevation,
    bool Shortcuts,
    bool StartupAtLogin)
{
    /// <summary>Conservative default — headless/test bundles claim nothing.</summary>
    public static PlatformCapabilities None { get; } =
        new("this platform", false, false, false, false, false, false, false, false);

    /// <summary>Human reason shown beside a capability-gated control.</summary>
    public string Unavailable => $"Not available on {PlatformName}";
}
