using System.Text;
using System.Text.Json;

namespace CryptoKey;

/// <summary>One session's bearer material — never persisted in the clear.</summary>
internal sealed class AuthTokens
{
    public string AccessToken { get; set; } = "";
    public string RefreshToken { get; set; } = "";
    public DateTime ExpiresAtUtc { get; set; }

    /// <summary>Usable without a refresh — GoTrue access tokens run ~1h.</summary>
    public bool Live => AccessToken.Length > 0 && ExpiresAtUtc > DateTime.UtcNow;

    /// <summary>Refresh-token present — a dead access token can still renew.</summary>
    public bool Renewable => RefreshToken.Length > 0;
}

/// <summary>
/// Session-token persistence: session.dat beside config.json, sealed by
/// <see cref="PlatformServices.Protector"/> (DPAPI on Windows, the Keychain
/// wrap on macOS — each with its own entropy tag, so a session blob can't
/// be swapped for a keyfile blob or vice versa). A same-user attacker can
/// delete the file (→ sign-in again), but DPAPI/Keychain keep them from
/// reading or replaying it elsewhere.
/// </summary>
internal static class TokenStore
{
    internal static readonly byte[] Entropy = Encoding.UTF8.GetBytes("CryptoKey.session.v1");

    public static string SessionPath => Path.Combine(ConfigStore.ConfigDir, "session.dat");

    /// <summary>Marker only — "an account signed in here at some point".</summary>
    public static bool Exists => File.Exists(SessionPath);

    /// <summary>Load + unseal; null when absent/corrupt/foreign-machine.</summary>
    public static AuthTokens? Load()
    {
        try
        {
            if (!File.Exists(SessionPath))
                return null;
            byte[] plain = Platform.Services.Protector.Unprotect(
                File.ReadAllBytes(SessionPath), Entropy);
            return JsonSerializer.Deserialize<AuthTokens>(plain);
        }
        catch (Exception)
        {
            return null; // corrupt or foreign — treated as no session
        }
    }

    /// <summary>Seal + write atomically; failures are silent (offline grace survives).</summary>
    public static void Save(AuthTokens tokens)
    {
        try
        {
            byte[] plain = JsonSerializer.SerializeToUtf8Bytes(tokens);
            byte[] blob = Platform.Services.Protector.Protect(plain, Entropy);
            Directory.CreateDirectory(ConfigStore.ConfigDir);
            AtomicFile.WriteAllBytes(SessionPath, blob);
        }
        catch (Exception)
        {
            // A failed save only narrows offline grace — the in-memory
            // session still authorizes this run.
        }
    }

    public static void Clear()
    {
        try { File.Delete(SessionPath); }
        catch (Exception) { }
    }
}
