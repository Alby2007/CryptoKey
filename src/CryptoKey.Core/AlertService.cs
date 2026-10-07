namespace CryptoKey;

/// <summary>
/// Remote alerting: POSTs security events to a user-chosen URL — an
/// ntfy.sh topic (Title header is honored) or any generic webhook (the
/// body is the payload). Fire-and-forget with a 4s timeout; the first
/// delivery failure is logged, later ones stay quiet. The payload is
/// "machine: event" — no secrets, and the URL is the user's own endpoint.
/// </summary>
internal static class AlertService
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(4) };
    private static int _failureLogged;

    /// <summary>
    /// L4 — only absolute https URLs are alert targets: the payload carries
    /// the machine name and the lock/tamper timeline; a plaintext POST
    /// hands that to any network watcher (and a planted http URL would
    /// have done exactly that).
    /// </summary>
    public static bool IsAllowedUrl(string url)
        => Uri.TryCreate(url, UriKind.Absolute, out Uri? u)
           && u.Scheme == Uri.UriSchemeHttps;

    /// <summary>Queue an event push. "" url = alerting off. Never throws.</summary>
    public static void Send(string url, string title, string body, Action<string>? log = null)
    {
        if (string.IsNullOrWhiteSpace(url))
            return;
        if (!IsAllowedUrl(url))
        {
            if (Interlocked.Exchange(ref _failureLogged, 1) == 0)
                log?.Invoke("Alert URL must be https://… — event dropped.");
            return;
        }
        _ = Task.Run(async () =>
        {
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Post, url)
                {
                    Content = new StringContent($"{Environment.MachineName}: {body}"),
                };
                // HTTP headers are ASCII-only — the em-dash would be
                // rejected on the wire. Body stays UTF-8.
                req.Headers.TryAddWithoutValidation("Title", $"CryptoKey: {title}");
                using var resp = await Http.SendAsync(req);
                resp.EnsureSuccessStatusCode();
            }
            catch (Exception ex)
            {
                if (Interlocked.Exchange(ref _failureLogged, 1) == 0)
                    log?.Invoke($"Alert delivery failed ({ex.Message}) — later failures stay quiet.");
            }
        });
    }
}
