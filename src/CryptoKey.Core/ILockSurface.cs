namespace CryptoKey;

/// <summary>
/// The thing that locks the machine. Two tiers per platform: the
/// overlay-class surface (per-monitor forms / fullscreen window) and the
/// secure surface (private desktop on Windows, display capture on macOS).
/// GuardService talks only to this interface; unlock/verify logic never
/// sees the difference.
/// </summary>
internal interface ILockSurface : IDisposable
{
    /// <summary>True on the overlay-class surface — the fallback tier GuardService
    /// drops to when the secure surface can't engage (and the mode the "overlay"
    /// LockMode pins to).</summary>
    bool IsOverlay { get; }

    /// <summary>Why the last <see cref="Engage"/> returned false, when it did.</summary>
    string? EngageError { get; }

    /// <summary>Raised with the buffered phrase when Enter is pressed —
    /// a char[] the handler must wipe after verifying.</summary>
    event Action<char[]>? PassphraseSubmitted;

    /// <summary>Dev-mode emergency exit (Ctrl+Alt+Shift+F12).</summary>
    event Action? PanicRequested;

    /// <summary>
    /// Security events the surface detects — "desktop-flap" per hostile
    /// input-desktop switch, "desktop-flap-storm" when they come in a
    /// burst. The classic surface never fires; the guard decides what to
    /// do with each (log always, alert/snap on storm).
    /// </summary>
    event Action<string>? SecurityEvent;

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
