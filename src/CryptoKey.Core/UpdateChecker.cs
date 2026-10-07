using System.Diagnostics;
using System.IO.Compression;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;

namespace CryptoKey;

/// <summary>A refused update — bad signature, hash mismatch, unsafe payload.</summary>
internal sealed class UpdateException : Exception
{
    public UpdateException(string message) : base(message) { }
}

/// <summary>A newer release found on GitHub — tag, version, asset URLs.</summary>
internal sealed class UpdateInfo
{
    public required string TagName { get; init; }
    public required Version Version { get; init; }
    public required string ZipUrl { get; init; }
    public required string ManifestUrl { get; init; }
    public required string SigUrl { get; init; }
    public string? Notes { get; init; }
    public DateTimeOffset PublishedAt { get; init; }
}

/// <summary>
/// GitHub-Releases update channel. Check hits <c>releases/latest</c> (which
/// already skips drafts/prereleases); a version strictly newer than this
/// build's stamp becomes a pending update. Apply downloads the payload zip
/// + SHA256SUMS manifest + signature, verifies the manifest against the
/// pinned maintainer key (see <see cref="ReleaseSigning"/>), the zip against
/// the manifest, then extracts to a staging dir — the staged exe drives the
/// actual install swap.
/// </summary>
internal static class UpdateChecker
{
    internal const string Repo = "Alby2007/CryptoKey";
    internal const string ZipName = "cryptokey-win-x64.zip";
    internal const string ManifestName = "SHA256SUMS.txt";
    internal const string SigName = "SHA256SUMS.sig";

    private static readonly HttpClient Http = new()
    {
        // Generous: the timeout covers the zip download too — a ~50 MB
        // payload on a slow link needs minutes, not seconds.
        Timeout = TimeSpan.FromMinutes(5),
        // api.github.com 403s requests without one.
        DefaultRequestHeaders = { { "User-Agent", "cryptokey" } },
    };

    /// <summary>This build's declared version — the BuildStamp prefix before '+'.</summary>
    public static Version CurrentVersion
        => Version.TryParse(CryptoKeyCli.BuildStamp.Split('+')[0], out Version? v)
            ? v : new Version(0, 0, 0);

    /// <summary>"v1.2.3" / "v1.2.3+build" → Version; anything else fails.</summary>
    public static bool TryParseTag(string tag, out Version version)
    {
        version = new Version(0, 0);
        if (string.IsNullOrWhiteSpace(tag) || tag[0] is not ('v' or 'V'))
            return false;
        ReadOnlySpan<char> rest = tag.AsSpan(1);
        int cut = rest.IndexOfAny('-', '+'); // -rc suffixes / +build metadata don't count
        if (cut >= 0)
            rest = rest[..cut];
        return Version.TryParse(rest, out version!);
    }

    /// <summary>Strictly newer than this build?</summary>
    public static bool IsNewer(Version remote, Version current)
        => remote.CompareTo(current) > 0;

    /// <summary>
    /// Ask GitHub for the latest release; null when nothing is newer or a
    /// required asset is missing. Transport/parse failures throw — callers
    /// (guard tick, CLI) treat them as "check failed", never as "up to date".
    /// </summary>
    public static async Task<UpdateInfo?> CheckAsync(CancellationToken ct = default)
    {
        // releases/latest 404s on a repo with no releases — that's a legit
        // "nothing newer", not a check failure.
        using HttpResponseMessage resp = await Http.GetAsync(
            $"https://api.github.com/repos/{Repo}/releases/latest", ct)
            .ConfigureAwait(false);
        if (resp.StatusCode == System.Net.HttpStatusCode.NotFound)
            return null;
        resp.EnsureSuccessStatusCode();
        using JsonDocument doc = await JsonDocument.ParseAsync(
            await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false),
            cancellationToken: ct).ConfigureAwait(false);
        JsonElement root = doc.RootElement;
        if (!TryParseTag(root.GetProperty("tag_name").GetString() ?? "",
                out Version remote) || !IsNewer(remote, CurrentVersion))
            return null;

        string? zip = null, manifest = null, sig = null;
        foreach (JsonElement a in root.GetProperty("assets").EnumerateArray())
        {
            string name = a.GetProperty("name").GetString() ?? "";
            string url = a.GetProperty("browser_download_url").GetString() ?? "";
            if (name == ZipName) zip = url;
            else if (name == ManifestName) manifest = url;
            else if (name == SigName) sig = url;
        }
        if (zip == null || manifest == null || sig == null)
            return null; // unsigned/incomplete release — never offered

        return new UpdateInfo
        {
            TagName = root.GetProperty("tag_name").GetString()!,
            Version = remote,
            ZipUrl = zip,
            ManifestUrl = manifest,
            SigUrl = sig,
            Notes = root.TryGetProperty("body", out JsonElement b)
                ? b.GetString() : null,
            PublishedAt = root.TryGetProperty("published_at", out JsonElement p)
                && DateTimeOffset.TryParse(p.GetString(), out DateTimeOffset at)
                ? at : default,
        };
    }

    /// <summary>
    /// Parse sha256sum-style lines: "<hex>  <name>" → name→hash map.
    /// `#` lines are comments — `# release: <tag>` binds the manifest to
    /// its release so an older signed payload can't be re-served as newer.
    /// </summary>
    public static Dictionary<string, string> ParseSha256Sums(string manifest)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string line in manifest.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            string t = line.Trim();
            if (t.StartsWith('#'))
                continue;
            int gap = t.IndexOf(' ');
            if (gap <= 0)
                continue;
            map[t[(gap + 1)..].TrimStart('*', ' ')] = t[..gap];
        }
        return map;
    }

    /// <summary>The `# release: <tag>` binding in a manifest, or null.</summary>
    public static string? ManifestTag(string manifest)
    {
        foreach (string line in manifest.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            string t = line.Trim();
            if (t.StartsWith("# release:", StringComparison.Ordinal))
                return t["# release:".Length..].Trim();
        }
        return null;
    }

    /// <summary>SHA-256 of a file — hex lowercase, the manifest's form.</summary>
    public static string Sha256Hex(string path)
        => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();

    /// <summary>
    /// Download + verify + extract to <paramref name="stagingDir"/>:
    /// manifest signature first (pinned maintainer key), then the zip hash
    /// from the manifest, then extract. Throws on any mismatch — the caller
    /// treats a throw as "update refused".
    /// </summary>
    public static async Task<string> FetchVerifiedAsync(
        UpdateInfo info, string stagingDir, Action<string>? log = null,
        CancellationToken ct = default)
    {
        string dir = Path.Combine(stagingDir, $"update-{info.TagName}");
        if (Directory.Exists(dir))
            Directory.Delete(dir, recursive: true); // stale attempt — wipe
        Directory.CreateDirectory(dir);

        string manifestPath = Path.Combine(dir, ManifestName);
        string sigPath = Path.Combine(dir, SigName);
        string zipPath = Path.Combine(dir, ZipName);
        await DownloadTo(info.ManifestUrl, manifestPath, ct).ConfigureAwait(false);
        await DownloadTo(info.SigUrl, sigPath, ct).ConfigureAwait(false);
        await DownloadTo(info.ZipUrl, zipPath, ct).ConfigureAwait(false);
        return VerifyAndExtract(info, manifestPath, sigPath, zipPath, dir, log);
    }

    /// <summary>
    /// The trust gate, pure-local: manifest signature → tag binding → zip
    /// hash → safe extract. Separated from the downloads so tests can drive
    /// it with fixture files.
    /// </summary>
    public static string VerifyAndExtract(
        UpdateInfo info, string manifestPath, string sigPath, string zipPath,
        string dir, Action<string>? log = null, string? publicKeyB64 = null)
    {
        byte[] manifestBytes = File.ReadAllBytes(manifestPath);
        byte[] sigBytes = File.ReadAllBytes(sigPath);
        if (!ReleaseSigning.Verify(manifestBytes, sigBytes, publicKeyB64))
            throw new UpdateException("release manifest signature rejected — " +
                "not signed by the pinned maintainer key");

        string manifest = System.Text.Encoding.UTF8.GetString(manifestBytes);
        // The tag binding is REQUIRED, not advisory: an unbound manifest
        // replayed under a newer release tag must fail closed, not pass
        // on absence.
        if (ManifestTag(manifest) is not string bound || bound != info.TagName)
            throw new UpdateException(
                $"release manifest is not bound to {info.TagName} — " +
                "refusing an unbound or mismatched payload");
        var sums = ParseSha256Sums(manifest);
        if (!sums.TryGetValue(ZipName, out string? wantHash)
                || !Sha256Hex(zipPath).Equals(wantHash, StringComparison.OrdinalIgnoreCase))
            throw new UpdateException("release zip hash mismatch — corrupt or tampered payload");

        string payload = Path.Combine(dir, "payload");
        // ExtractToDirectory rejects path-traversal entries on modern .NET.
        ZipFile.ExtractToDirectory(zipPath, payload, overwriteFiles: true);

        // The staged exe's own version must be the tag we fetched — a
        // payload re-served under a foreign tag dies here even if a
        // signing lapse ever let its manifest through. A versionless exe
        // (test fixtures) can't be judged — skip rather than guess.
        string stagedExe = Path.Combine(payload, "cryptokey.exe");
        if (File.Exists(stagedExe))
        {
            string? pv = FileVersionInfo.GetVersionInfo(stagedExe).ProductVersion;
            if (!string.IsNullOrEmpty(pv)
                && !pv.Equals(info.TagName.TrimStart('v', 'V'),
                    StringComparison.OrdinalIgnoreCase))
                throw new UpdateException(
                    $"staged cryptokey.exe reports version {pv}, not " +
                    $"{info.TagName} — refusing a mismatched payload");
        }
        log?.Invoke($"Update {info.TagName} verified + staged.");
        return payload;
    }

    /// <summary>Download to a `.part` then rename — an interrupted fetch never leaves a "complete" file.</summary>
    private static async Task DownloadTo(string url, string path, CancellationToken ct)
    {
        string part = path + ".part";
        try
        {
            await using (FileStream fs = File.Create(part))
            {
                using HttpResponseMessage r = await Http.GetAsync(
                    url, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                r.EnsureSuccessStatusCode();
                await r.Content.CopyToAsync(fs, ct).ConfigureAwait(false);
            }
            File.Move(part, path, overwrite: true);
        }
        catch
        {
            try { File.Delete(part); } catch { }
            throw;
        }
    }
}
