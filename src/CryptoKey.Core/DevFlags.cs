namespace CryptoKey;

/// <summary>
/// L5 — the <c>--dev</c> panic combo exists for debug builds only. In a
/// shipped Release binary the flag parses to nothing: the combo is a
/// no-questions-asked unlock path, and a launch argument is something a
/// same-user process (or the updater's relaunch line, or a hijacked
/// scheduled task) fully controls. Every parse site funnels through
/// <see cref="ParseDev"/> so Release can't leak a panic path.
/// </summary>
internal static class DevFlags
{
#if DEBUG
    public const bool Available = true;
#else
    public const bool Available = false;
#endif

    /// <summary><c>--dev</c> counts only in debug builds.</summary>
    public static bool ParseDev(IEnumerable<string> args)
        => Available && args.Contains("--dev", StringComparer.OrdinalIgnoreCase);
}
