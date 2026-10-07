using System.Text;
using System.Text.Json;

namespace CryptoKey;

/// <summary>Throttle counters that survive a restart — L6.</summary>
internal sealed class ThrottleState
{
    /// <summary>Recovery-phrase failure streak on the lock surface.</summary>
    public int PhraseFailures { get; set; }

    /// <summary>Frozen-until instant for the phrase input (UTC).</summary>
    public DateTime PhraseCooldownUntilUtc { get; set; }

    /// <summary>Account-gate failure streak toward the next lockout.</summary>
    public int AuthFailures { get; set; }

    /// <summary>Escalating lockout length (doubles per strike, caps at 900s).</summary>
    public int AuthCooldownSeconds { get; set; } = 30;

    /// <summary>Locked-until instant for the account gate (UTC).</summary>
    public DateTime AuthLockedUntilUtc { get; set; }
}

/// <summary>
/// A restart must not hand the brute-forcer a fresh ladder — the phrase
/// and auth throttles persist in <c>throttle.dat</c>, sealed by
/// <see cref="PlatformServices.Protector"/> (DPAPI/Keychain) like the
/// session tokens. Monotonic: failures only ever ratchet the counters up;
/// a real success is the only reset.
/// Honest bound: a same-user attacker can DELETE the file — protection
/// covers contents, not existence. Deletion buys them a fresh ladder but
/// nothing more; the ladder is a speedbump, not a wall.
/// </summary>
internal static class ThrottleStore
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("CryptoKey.throttle.v1");
    private static readonly object Gate = new();
    private static ThrottleState? _shared;

    internal static string StorePath => Path.Combine(ConfigStore.ConfigDir, "throttle.dat");

    /// <summary>The process-wide counters — both services mutate this copy.</summary>
    public static ThrottleState Shared
    {
        get { lock (Gate) return _shared ??= Load(); }
    }

    private static ThrottleState Load()
    {
        try
        {
            if (!File.Exists(StorePath))
                return new ThrottleState();
            byte[] plain = Platform.Services.Protector.Unprotect(
                File.ReadAllBytes(StorePath), Entropy);
            return JsonSerializer.Deserialize<ThrottleState>(plain)
                ?? new ThrottleState();
        }
        catch (Exception)
        {
            return new ThrottleState(); // corrupt or foreign — fresh ladder
        }
    }

    /// <summary>Seal + write the shared state atomically; failures are silent.</summary>
    public static void Save()
    {
        lock (Gate)
        {
            if (_shared == null)
                return;
            try
            {
                byte[] plain = JsonSerializer.SerializeToUtf8Bytes(_shared);
                byte[] blob = Platform.Services.Protector.Protect(plain, Entropy);
                Directory.CreateDirectory(ConfigStore.ConfigDir);
                AtomicFile.WriteAllBytes(StorePath, blob);
            }
            catch (Exception)
            {
                // Persistence is best-effort — in-memory throttle still applies.
            }
        }
    }

    /// <summary>Test seam — drop the cached copy only. The sealed file
    /// persists, so the next read reloads it: this simulates a process
    /// restart, which is exactly what L6 tests.</summary>
    internal static void ResetCache()
    {
        lock (Gate) _shared = null;
    }

    /// <summary>Test seam — a fully clean slate: cache AND persisted file.</summary>
    internal static void Clear()
    {
        lock (Gate)
        {
            _shared = null;
            try { if (File.Exists(StorePath)) File.Delete(StorePath); } catch { }
        }
    }
}
