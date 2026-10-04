namespace CryptoKey;

internal enum GuardState
{
    Unlocked,
    Locked,
    Paused,
}

internal sealed record StatusSnapshot(
    GuardState State,
    bool KeyPresent,
    string? Model,
    string? LastVerifyFailure,
    DateTime? PausedUntil);
