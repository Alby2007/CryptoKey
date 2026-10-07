using System.Text.Json;
using System.Text.Json.Serialization;

namespace CryptoKey;

/// <summary>
/// Supabase project wiring — `supabase.json` beside the executable:
/// <code>{ "projectUrl": "https://xyz.supabase.co", "anonKey": "eyJ…" }</code>
/// The anon key is designed to ship inside clients (GoTrue treats it as a
/// public credential — Supabase RLS is what protects data, and this app
/// creates no tables at all). A missing/invalid file doesn't stop the
/// guard: auth just reports <see cref="IsValid">false</see> and every
/// online flow shows a configuration banner instead.
/// </summary>
internal sealed class SupabaseConfig
{
    [JsonPropertyName("projectUrl")]
    public string ProjectUrl { get; set; } = "";

    [JsonPropertyName("anonKey")]
    public string AnonKey { get; set; } = "";

    /// <summary>auth/v1 REST base — every GoTrue call hangs off this.</summary>
    public string AuthBase => ProjectUrl.TrimEnd('/') + "/auth/v1";

    /// <summary>Both fields present and the URL is an https:// absolute URI.</summary>
    public bool IsValid
        => Uri.TryCreate(ProjectUrl, UriKind.Absolute, out Uri? u)
           && u.Scheme == Uri.UriSchemeHttps
           && AnonKey.Length >= 20;

    /// <summary>
    /// Release builds resolve supabase.json ONLY beside the executable —
    /// the shipped install dir. The env-var override and the config-dir
    /// fallback exist for tests/dev and are compiled out of Release: both
    /// are user-writable paths, and this file is the auth trust root — a
    /// swapped copy would steer every credential somewhere else. Bound
    /// installs additionally pin the project in the account record
    /// (<see cref="AuthService.TrustRootMismatch"/>).
    /// </summary>
    public static string CandidatePath()
    {
#if DEBUG
        if (Environment.GetEnvironmentVariable("CRYPTOKEY_SUPABASE_JSON")
                is { Length: > 0 } overridePath)
            return overridePath;
#endif
        string besideExe = Path.Combine(AppContext.BaseDirectory, "supabase.json");
        if (File.Exists(besideExe))
            return besideExe;
#if DEBUG
        return Path.Combine(ConfigStore.ConfigDir, "supabase.json");
#else
        return besideExe; // missing — TryLoad reports "not configured"
#endif
    }

    /// <summary>
    /// Load the config. Never throws — a missing file returns null with a
    /// null error (simply "not configured"), a malformed file returns null
    /// with the parse error (misconfigured — UI banners it loudly).
    /// </summary>
    public static SupabaseConfig? TryLoad(out string? error)
    {
        error = null;
        string path = CandidatePath();
        if (!File.Exists(path))
            return null;
        try
        {
            var cfg = JsonSerializer.Deserialize<SupabaseConfig>(
                File.ReadAllText(path));
            if (cfg == null || !cfg.IsValid)
            {
                error = $"supabase.json at {path} is present but invalid — " +
                    "needs an https projectUrl and the anon key.";
                return null;
            }
            return cfg;
        }
        catch (Exception ex)
        {
            error = $"supabase.json at {path} failed to parse: {ex.Message}";
            return null;
        }
    }
}
