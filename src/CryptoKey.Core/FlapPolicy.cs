namespace CryptoKey;

/// <summary>
/// Desktop-flap classification: is the current input desktop hostile?
/// Any same-session process can SwitchDesktop input away from the lock
/// desktop — the mechanism --release-desktop uses — so while engaged the
/// surface watches and yanks foreign desktops back.
///
/// Legit: our own lock desktop, and the Winlogon SAS screen (CAD/UAC) —
/// which reports either by name or by OpenInputDesktop failing outright
/// (its DACL denies us while SAS is up; the unreadable desktop IS the
/// tell). Everything else — "Default", attacker-created desktops — is a
/// flap: re-switch and count.
/// </summary>
internal static class FlapPolicy
{
    /// <summary>
    /// Base name of <see cref="SecureLockSurface"/>'s private desktop — the
    /// surface may suffix it (-1, -2…) when a squatter survives eviction on
    /// the shared object, so callers always pass the *active* name.
    /// </summary>
    internal const string LockDesktop = "CryptoKeyLock";

    /// <param name="lockDesktopName">The active lock desktop's exact name —
    /// exact match only; a hostile "CryptoKeyLock-evil" must not whitelist.</param>
    public static bool IsHostile(string? desktopName, bool openFailed, string lockDesktopName)
    {
        if (openFailed)
            return false; // Winlogon ACL-deny — the SAS tell
        if (desktopName == null)
            return true; // a readable desktop we can't name is still foreign
        return !desktopName.Equals(lockDesktopName, StringComparison.OrdinalIgnoreCase)
            && !desktopName.Equals("Winlogon", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// ~3s of unreadable input desktop (~300ms ticks) before failing closed.
    /// OpenInputDesktop ACL-deny is the *normal* SAS tell — a user at CAD
    /// shouldn't instant-lock — but an indefinitely blind monitor is an
    /// infinite switching blind spot: at the threshold, pin at OS auth.
    /// </summary>
    internal const int UnreadableTicksBeforeLock = 10;

    /// <summary>
    /// Input furniture that legitimately lands on whatever desktop is
    /// active (the language pill, the IME host) — winlogon spawning a
    /// foreign *app* onto the lock desktop is the intruder class; these
    /// aren't. An intruder verdict requires a resolved name NOT here.
    /// </summary>
    public static bool IsBenignDesktopResident(string procName)
        => procName.Equals("ctfmon", StringComparison.OrdinalIgnoreCase)
           || procName.Equals("TextInputHost", StringComparison.OrdinalIgnoreCase);

    /// <summary>Sentinel verdict for one foreign top-level window on the lock desktop.</summary>
    public enum ForeignWindowVerdict
    {
        /// <summary>Input furniture — skip entirely (not even "foreign").</summary>
        Benign,
        /// <summary>Visible foreign window — conclusive intruder, named or not.</summary>
        Intruder,
        /// <summary>Invisible or otherwise inconclusive — accrues toward the storm latch.</summary>
        Inconclusive,
    }

    /// <summary>
    /// One foreign window's sentinel verdict. A VISIBLE foreign top-level
    /// window is conclusive even when the process name won't resolve
    /// (protected/elevated) — nothing legit paints on a private desktop.
    /// Invisible windows are inconclusive: a hidden thread can still plant
    /// hooks, but it can't act as an intruder surface.
    /// </summary>
    public static ForeignWindowVerdict ClassifyForeignWindow(
        bool visible, string? procName)
    {
        if (procName != null && IsBenignDesktopResident(procName))
            return ForeignWindowVerdict.Benign;
        return visible ? ForeignWindowVerdict.Intruder : ForeignWindowVerdict.Inconclusive;
    }

    /// <summary>
    /// Supervisor-death fail-closed gate: locked + enabled + a live supervisor
    /// that just died = kill-order evidence → pin at OS auth once per
    /// transition. Unlocked, disabled, or never-alive can't fire.
    /// </summary>
    public static bool ShouldEscalateSupervisorDeath(
        bool locked, bool enabled, bool wasAlive, bool alive)
        => locked && enabled && wasAlive && !alive;
}

/// <summary>
/// Consecutive OpenInputDesktop failures while engaged — fires once at the
/// threshold, then holds silent until a readable tick resets the streak.
/// </summary>
public sealed class UnreadableStreak
{
    private int _ticks;
    private bool _latched;

    /// <summary>Returns true exactly once per streak — at the threshold.</summary>
    public bool RecordUnreadable()
    {
        _ticks++;
        if (_latched || _ticks < FlapPolicy.UnreadableTicksBeforeLock)
            return false;
        _latched = true;
        return true;
    }

    /// <summary>
    /// The caller chose not to act on the firing (e.g. our own OS-lock is
    /// the reason the desktop is unreadable) — un-latch so the next
    /// unreadable tick re-fires instead of the streak staying silent.
    /// </summary>
    public void ReleaseLatch() => _latched = false;

    /// <summary>A readable tick re-arms the streak.</summary>
    public void Reset()
    {
        _ticks = 0;
        _latched = false;
    }
}

/// <summary>
/// Sliding-window flap counter: ≥3 hostile flaps inside 10s is a storm —
/// scripted switching, not a stray CAD. The window stays armed while
/// flaps keep landing inside it (each returns true → the caller's
/// idempotent LockWorkStation keeps firing), and ages out when the
/// attack stops so the next one re-accumulates honestly.
/// </summary>
internal sealed class FlapCounter
{
    internal static readonly TimeSpan Window = TimeSpan.FromSeconds(10);
    internal const int Threshold = 3;

    private readonly Queue<DateTime> _flaps = new();

    /// <summary>Record a hostile flap at <paramref name="now"/>; true while ≥3 in window.</summary>
    public bool Record(DateTime now)
    {
        _flaps.Enqueue(now);
        while (_flaps.Count > 0 && now - _flaps.Peek() > Window)
            _flaps.Dequeue();
        return _flaps.Count >= Threshold;
    }

    public void Reset() => _flaps.Clear();
}
