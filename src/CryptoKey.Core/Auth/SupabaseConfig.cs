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
    /// Resolution order: <c>CRYPTOKEY_SUPABASE_JSON</c> (tests/relocated
    /// installs), then supabase.json beside the exe, then beside config.json.
    /// </summary>
    public static string CandidatePath()
    {
        if (Environment.GetEnvironmentVariable("CRYPTOKEY_SUPABASE_JSON")
                is { Length: > 0 } overridePath)
            return overridePath;
        string besideExe = Path.Combine(AppContext.BaseDirectory, "supabase.json");
        if (File.Exists(besideExe))
            return besideExe;
        return Path.Combine(ConfigStore.ConfigDir, "supabase.json");
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
