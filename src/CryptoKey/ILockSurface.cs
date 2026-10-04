namespace CryptoKey;

/// <summary>
/// The thing that locks the machine. Two implementations: the classic
/// on-desktop overlay (<see cref="ClassicLockSurface"/>) and the secure
/// private-desktop surface (<see cref="SecureLockSurface"/>). GuardService
/// talks only to this interface; unlock/verify logic never sees the difference.
/// </summary>
internal interface ILockSurface : IDisposable
{
    /// <summary>Raised with the buffered passphrase when Enter is pressed.</summary>
    event Action<string>? PassphraseSubmitted;

    /// <summary>Dev-mode emergency exit (Ctrl+Alt+Shift+F12).</summary>
    event Action? PanicRequested;

    /// <summary>
    /// Show the lock and contain input. False means the surface could not
    /// engage — the caller falls back (secure → classic). The lock must
    /// always land.
    /// </summary>
    bool Engage();

    /// <summary>
    /// Return the user's input (and desktop) and tear the surface down.
    /// False means input could not be returned — the surface stays engaged
    /// and functional so the lock still works; retry on the next unlock.
    /// </summary>
    bool Disengage();

    /// <summary>
    /// Fail-dead path, callable from any thread: free input NOW. For the
    /// secure surface this must also switch the input desktop back — an
    /// unhook without a switch-back leaves the user stranded.
    /// </summary>
    void ReleaseInput();

    /// <summary>Re-apply cursor confinement (classic overlay only).</summary>
    void ReassertClip();

    void SetAnimations(bool enabled);
    void SetStatus(string message);
    void ResetStatus();
    void SetPassphraseLength(int len);
    void SetFailedAttempts(int count);
    void SetCooldown(DateTime? until);
}
