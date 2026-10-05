namespace CryptoKey;

internal enum GuardState
{
    Unlocked,
    Locked,
    Paused,
}

/// <summary>Vault state for the dashboard badge — null hides it entirely.</summary>
internal sealed record VaultStatus(VaultState State, string MountPoint);

internal sealed record StatusSnapshot(
    GuardState State,
    bool KeyPresent,
    string? Model,
    string? LastVerifyFailure,
    DateTime? PausedUntil,
    string? TamperNote,
    bool KeyFactorArmed,
    bool WatchdogAlive,
    VaultStatus? Vault = null);
