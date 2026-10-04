namespace CryptoKey;

/// <summary>
/// Passphrase-failure freeze ladder: attempts 1-2 are free, then 15s
/// doubling (15/30/60/120/240) capped at 300s. Extracted so the ladder is
/// unit-testable — GuardService applies it inside the keyboard hook.
/// </summary>
internal static class Backoff
{
    public static int Seconds(int failedAttempts)
        => failedAttempts < 3 ? 0 : Math.Min(15 << Math.Min(failedAttempts - 3, 5), 300);
}
