using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace CryptoKey;

/// <summary>Where the account gate currently stands — drives UI copy + routing.</summary>
internal enum AuthGateState
{
    /// <summary>supabase.json missing/invalid — online auth impossible.</summary>
    Unconfigured,
    /// <summary>No account was ever linked on this install (no record, no session file).</summary>
    Unenrolled,
    /// <summary>An account is bound but nothing authorizes this session yet.</summary>
    Locked,
    /// <summary>Unlocked via the local verifier (or tokens present but expired offline).</summary>
    OfflineUnlocked,
    /// <summary>Live bearer tokens — fully online session.</summary>
    Online,
}

internal sealed record AuthResult(bool Ok, string? Error,
    bool NeedsConfirm = false, bool Offline = false)
{
    public static AuthResult Fail(string error) => new(false, error);
}

/// <summary>
/// The one account authority: Supabase Auth (GoTrue REST) for identity, a
/// locally-attested PBKDF2 verifier for offline grace and sensitive-op
/// authorization. The account gates the dashboard + mutating ops ONLY —
/// the USB key and recovery phrase remain the sole workstation lock
/// factors, and the guard runs regardless of account state.
///
/// One instance per process (<see cref="Current"/>): the engine binds it to
/// the enrolled config, the auth window drives it pre-enrollment. Record
/// writes go through <see cref="RecordPersisted"/> so the engine can mark
/// the keyfile attestation stale (covered fields must re-bind on the next
/// key verify — password change/relink require the key present).
/// </summary>
internal sealed class AuthService
{
    private static readonly HttpClient SharedHttp = new()
    {
        Timeout = TimeSpan.FromSeconds(10),
    };

    private static AuthService? _current;

    /// <summary>The process-wide account service — created on first use.</summary>
    public static AuthService Current => _current ??= Create();

    /// <summary>Tests and explicit init paths override the ambient instance.</summary>
    internal static void SetCurrent(AuthService? service) => _current = service;

    /// <summary>Load supabase.json and wire the default shared client.</summary>
    public static AuthService Create()
        => new(SupabaseConfig.TryLoad(out _), null);

    private readonly SupabaseConfig? _cfg;
    private readonly HttpClient _http;
    private readonly object _sync = new();

    private KeyConfig? _config;
    private AccountRecord? _record;
    private AuthTokens? _tokens;
    private bool _unlocked;          // verifier satisfied this run — session-scope
    private bool _attestationClean = true;
    private int _failures;           // local attempt limiter (in-memory speedbump)
    private DateTime _lockedUntil;
    private int _cooldownSeconds = 30;
    private bool _refreshing;

    /// <param name="handler">Test seam — production uses one static HttpClient.</param>
    public AuthService(SupabaseConfig? config, HttpMessageHandler? handler)
    {
        _cfg = config;
        _http = handler == null ? SharedHttp : new HttpClient(handler);
        _tokens = TokenStore.Load();
    }

    // ---------------------------------------------------------- state

    /// <summary>supabase.json parsed — without it no online flow can run.</summary>
    public bool Configured => _cfg != null;

    /// <summary>
    /// The bound account record — config-attested once enrolled, the
    /// pending file before that. An incomplete record is treated as absent
    /// (fail closed).
    /// </summary>
    public AccountRecord? Record
    {
        get { lock (_sync) return _record?.IsComplete == true ? _record : null; }
    }

    /// <summary>
    /// Does this install have an account credential at all? Record OR a
    /// pending record OR a prior session file means "enrolled" — a config
    /// with its account section deleted still gates ops while a session or
    /// staging file marks the install (a clean sign-out plus a delete is
    /// the documented way to remove an account, and then the gate lifts).
    /// </summary>
    public bool Gating =>
        Record != null || TokenStore.Exists || PendingStore.Exists;

    /// <summary>
    /// A pre-enrollment record is staged in account.pending.json — the
    /// first-run router resumes at sign-in instead of showing create.
    /// </summary>
    public bool HasPending => PendingStore.Exists;

    /// <summary>
    /// This run may perform gated ops: live session or verifier-unlocked —
    /// AND the attestation must be clean. A grafted/edited account record
    /// flips <see cref="_attestationClean"/> off on the next key verify;
    /// while it's dirty NOTHING authorizes on any path (UI tollbooth,
    /// IPC trailer, offline verifier) until a key-fenced relink or
    /// recovery rewrites the record.
    /// </summary>
    public bool Authorized
    {
        get
        {
            lock (_sync)
                return _attestationClean && (_unlocked || (_tokens?.Live ?? false));
        }
    }

    /// <summary>
    /// A signed-in session is driving this run — live bearer tokens or the
    /// offline verifier armed. The account session is the master switch
    /// for the guard's auto-lock machinery (key removal, startup, resume,
    /// idle, pause-expiry): unsigned, key pulls are just USB events.
    /// Unlock paths never consult it — the key and the recovery phrase
    /// always open a locked box; locking is the safe direction.
    /// </summary>
    public bool SessionLive
    {
        get
        {
            lock (_sync)
                return _unlocked || (_tokens?.Live ?? false);
        }
    }

    public AuthGateState State
    {
        get
        {
            lock (_sync)
            {
                if (_unlocked || (_tokens?.Live ?? false))
                    return _tokens?.Live == true ? AuthGateState.Online
                        : AuthGateState.OfflineUnlocked;
                if (!Configured && Record == null && !TokenStore.Exists
                    && !PendingStore.Exists)
                    return AuthGateState.Unconfigured;
                return Record == null && !TokenStore.Exists && !PendingStore.Exists
                    ? AuthGateState.Unenrolled
                    : AuthGateState.Locked;
            }
        }
    }

    /// <summary>Seconds left on the local throttle; 0 when clear to try.</summary>
    public int CooldownRemaining
    {
        get
        {
            lock (_sync)
            {
                double left = (_lockedUntil - DateTime.UtcNow).TotalSeconds;
                return Math.Max(0, (int)Math.Ceiling(left));
            }
        }
    }

    /// <summary>
    /// Raised after the record is written to <see cref="KeyConfig.Account"/> —
    /// the engine hooks this to mark the keyfile attestation dirty so the
    /// next verify re-binds quietly.
    /// </summary>
    public event Action? RecordPersisted;

    /// <summary>
    /// Point the service at the live config (engine start, post-enroll,
    /// reload). The pending file is the fallback record source when no
    /// config exists yet — and a config WITH an account shadows a stale
    /// pending file, which then gets cleaned up.
    /// </summary>
    public void BindConfig(KeyConfig? config)
    {
        lock (_sync)
        {
            _config = config;
            _record = config?.Account ?? PendingStore.Load();
            if (config?.Account != null)
                PendingStore.Clear(); // enrolled record wins; drop the staging file
        }
    }

    /// <summary>
    /// The attestation-health flag — the engine sets it from each keyfile
    /// verify. A grafted/tampered account section flips it false, and
    /// sensitive ops stay refused even if the grafted verifier would match
    /// the attacker's password.
    /// </summary>
    public void SetAttestationClean(bool clean)
    {
        lock (_sync) _attestationClean = clean;
    }

    private void PersistLocked()
    {
        if (_config != null)
        {
            _config.Account = _record;
            ConfigStore.Save(_config);   // throws → caller hears it
            RecordPersisted?.Invoke();   // engine → MarkConfigDirty
        }
        else
        {
            PendingStore.Save(_record);  // pre-enrollment staging file
        }
    }

    /// <summary>
    /// Persist the current record — used by the enrollment fold after the
    /// first config exists.
    /// </summary>
    public void PersistRecord()
    {
        lock (_sync) PersistLocked();
    }

    // ---------------------------------------------------------- throttle

    /// <summary>False while the in-memory limiter is cooling down.</summary>
    private bool Throttled(out string error)
    {
        lock (_sync)
        {
            int left = CooldownRemaining;
            if (left <= 0)
            {
                error = "";
                return false;
            }
            error = $"Too many attempts — try again in {left}s.";
            return true;
        }
    }

    private void NoteFailure()
    {
        lock (_sync)
        {
            _failures++;
            if (_failures >= 5)
            {
                _lockedUntil = DateTime.UtcNow.AddSeconds(_cooldownSeconds);
                _cooldownSeconds = Math.Min(_cooldownSeconds * 2, 900);
                _failures = 0;
            }
        }
    }

    private void NoteSuccess()
    {
        lock (_sync)
        {
            _failures = 0;
            _cooldownSeconds = 30;
            _lockedUntil = default;
        }
    }

    // ---------------------------------------------------------- authorization

    /// <summary>
    /// The sensitive-op check: live session → ok; a supplied password is
    /// verified against the local verifier (works fully offline) and arms
    /// this run's authorization on success. Never throws.
    /// </summary>
    public bool Authorize(string? password, out string error)
    {
        lock (_sync)
        {
            if (!_attestationClean)
            {
                error = "account data failed integrity check — relink required";
                return false;
            }
            if (_unlocked || (_tokens?.Live ?? false))
            {
                error = "";
                return true;
            }
        }
        if (password == null)
        {
            error = "AUTH_REQUIRED";
            return false;
        }
        if (Throttled(out error))
            return false;
        bool ok = Record?.VerifyPassword(password) == true;
        if (ok)
        {
            lock (_sync) _unlocked = true;
            NoteSuccess();
            error = "";
        }
        else
        {
            NoteFailure();
            error = "wrong account password";
        }
        return ok;
    }

    /// <summary>Same as <see cref="Authorize"/> for the auth window's offline path.</summary>
    public AuthResult TryUnlockOffline(string password)
    {
        lock (_sync)
        {
            if (!_attestationClean)
                return AuthResult.Fail(
                    "account data failed integrity check — relink required");
        }
        if (Throttled(out string throttleErr))
            return AuthResult.Fail(throttleErr);
        if (Record?.VerifyPassword(password) != true)
        {
            NoteFailure();
            return AuthResult.Fail(Record == null
                ? "No account is linked on this install."
                : "Wrong password.");
        }
        lock (_sync) _unlocked = true;
        NoteSuccess();
        return new AuthResult(true, null, Offline: true);
    }

    // ---------------------------------------------------------- GoTrue REST

    private HttpRequestMessage Req(HttpMethod method, string path)
    {
        var req = new HttpRequestMessage(method, _cfg!.AuthBase + path);
        req.Headers.Add("apikey", _cfg.AnonKey);
        return req;
    }

    private static HttpRequestMessage Json(HttpRequestMessage req, object body)
    {
        req.Content = new StringContent(
            JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
        return req;
    }

    private static string? ErrorMessage(JsonElement root)
    {
        // GoTrue serves two shapes: {error_code,msg} and {error,error_description}.
        foreach (string key in new[] { "msg", "error_description", "message", "error" })
            if (root.TryGetProperty(key, out JsonElement v) && v.ValueKind == JsonValueKind.String)
                return v.GetString();
        return null;
    }

    /// <summary>Parse a session response → tokens + identity; null when absent.</summary>
    private static AuthTokens? ParseTokens(JsonElement root)
    {
        if (!root.TryGetProperty("access_token", out JsonElement at)
            || at.ValueKind != JsonValueKind.String)
            return null;
        var tokens = new AuthTokens
        {
            AccessToken = at.GetString()!,
            RefreshToken = root.TryGetProperty("refresh_token", out JsonElement rt)
                ? rt.GetString() ?? "" : "",
            ExpiresAtUtc = DateTime.UtcNow.AddSeconds(
                root.TryGetProperty("expires_in", out JsonElement ex)
                && ex.TryGetInt32(out int secs) ? secs : 3600),
        };
        return tokens;
    }

    private static (string Id, string Email)? ParseUser(JsonElement root)
    {
        JsonElement user = root;
        if (root.TryGetProperty("user", out JsonElement nested)
            && nested.ValueKind == JsonValueKind.Object)
            user = nested;
        string? id = user.TryGetProperty("id", out JsonElement i) ? i.GetString() : null;
        string? email = user.TryGetProperty("email", out JsonElement e) ? e.GetString() : null;
        return id is { Length: > 0 } && email is { Length: > 0 } ? (id, email) : null;
    }

    /// <summary>
    /// Identity check for record-binding paths: a bound install is
    /// single-tenant, so a successful credential response for a DIFFERENT
    /// account must not silently rebind the verifier — that's how a
    /// foreign account's password would end up gating this machine. A
    /// foreign identity goes through the key-fenced relink flow instead
    /// (<paramref name="allowRebind"/> — the caller enforces key presence).
    /// </summary>
    private static bool SameIdentity(AccountRecord bound,
        (string Id, string Email)? user, string? emailFallback)
    {
        // A placeholder id ("unknown" — the unconfirmed-email path writes
        // one when the response withholds the user object) carries no real
        // identity: the bound EMAIL is the claim to compare, and the first
        // confirmed sign-in then upgrades the record to the real id.
        if (user is { } u && bound.UserId != "unknown")
            return bound.UserId.Equals(u.Id, StringComparison.Ordinal);
        return bound.Email.Equals((user?.Email ?? emailFallback ?? "").Trim(),
            StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Establish the session + local verifier after a token-bearing response.
    /// The verifier is re-derived from the password in hand every sign-in —
    /// so a password changed elsewhere takes effect locally on first
    /// successful online sign-in with the NEW password.
    /// </summary>
    private AuthResult Establish(JsonElement root, string password,
        string? emailFallback, bool allowRebind = false)
    {
        AuthTokens? tokens = ParseTokens(root);
        if (tokens == null)
            return new AuthResult(false, null, NeedsConfirm: true);
        var user = ParseUser(root);
        lock (_sync)
        {
            if (!allowRebind && !_attestationClean)
                return AuthResult.Fail(
                    "account data failed integrity check — relink required");
            if (!allowRebind && Record is { } bound
                && !SameIdentity(bound, user, emailFallback))
            {
                return AuthResult.Fail(
                    "that isn't the account bound to this install — " +
                    "use Relink to bind a different one");
            }
            AccountRecord? prev = _record;
            if (user is { } u)
                _record = AccountRecord.Create(u.Id, u.Email, password);
            else if (emailFallback != null)
                _record = AccountRecord.Create(
                    _record?.UserId ?? "unknown", emailFallback, password);
            try { PersistLocked(); }
            catch (Exception ex)
            {
                _record = prev; // keep memory honest with the disk that refused
                return AuthResult.Fail($"account record save failed: {ex.Message}");
            }
            // A key-fenced record write IS the sanctioned heal — the pending
            // reattest re-binds the whole canon on the next verify, so the
            // dirty flag can lift now rather than one verify-cycle late.
            if (!_attestationClean)
                _attestationClean = true;
            _tokens = tokens;
            TokenStore.Save(tokens);
            _unlocked = true;
        }
        NoteSuccess();
        return new AuthResult(true, null);
    }

    /// <summary>Create the account — the first-run path. email-confirm-off returns a session.</summary>
    public async Task<AuthResult> SignUp(string email, string password)
    {
        if (!Configured)
            return AuthResult.Fail("Supabase isn't configured (supabase.json).");
        if (Throttled(out string throttleErr))
            return AuthResult.Fail(throttleErr);
        try
        {
            using var req = Json(Req(HttpMethod.Post, "/signup"),
                new { email, password });
            using HttpResponseMessage resp = await _http.SendAsync(req);
            string body = await resp.Content.ReadAsStringAsync();
            JsonElement root;
            try { root = JsonDocument.Parse(body).RootElement; }
            catch (Exception) { return AuthResult.Fail("signup returned unreadable JSON"); }

            if (!resp.IsSuccessStatusCode)
            {
                NoteFailure();
                return AuthResult.Fail(
                    $"Sign-up failed ({(int)resp.StatusCode}): " +
                    (ErrorMessage(root) ?? resp.ReasonPhrase));
            }
            AuthResult r = Establish(root, password, email, allowRebind: false);
            if (r.NeedsConfirm)
                return new AuthResult(true,
                    "Account created — confirm the email Supabase sent, then sign in.",
                    NeedsConfirm: true);
            return r;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException
            or OperationCanceledException)
        {
            NoteFailure();
            return AuthResult.Fail(
                "Couldn't reach the server — check the connection and try again.");
        }
    }

    /// <summary>
    /// Sign in online; on network failure a linked account falls back to the
    /// verifier. <paramref name="relink"/> permits binding a DIFFERENT
    /// account — callers must fence that on the enrolled key's presence
    /// (the relink UI face does).
    /// </summary>
    public async Task<AuthResult> SignIn(string email, string password,
        bool relink = false)
    {
        lock (_sync)
        {
            if (!relink && !_attestationClean)
                return AuthResult.Fail(
                    "account data failed integrity check — relink required");
        }
        if (!Configured)
            return OfflineOr(email, password);
        if (Throttled(out string throttleErr))
            return AuthResult.Fail(throttleErr);
        try
        {
            using var req = Json(Req(HttpMethod.Post, "/token?grant_type=password"),
                new { email, password });
            using HttpResponseMessage resp = await _http.SendAsync(req);
            string body = await resp.Content.ReadAsStringAsync();
            JsonElement root;
            try { root = JsonDocument.Parse(body).RootElement; }
            catch (Exception) { root = default; }

            if (!resp.IsSuccessStatusCode)
            {
                string? msg = root.ValueKind == JsonValueKind.Object
                    ? ErrorMessage(root) : null;
                bool unconfirmed =
                    root.ValueKind == JsonValueKind.Object
                    && (root.TryGetProperty("error_code", out JsonElement ec)
                            && ec.GetString() == "email_not_confirmed"
                        || msg?.Contains("not confirmed",
                            StringComparison.OrdinalIgnoreCase) == true);
                if (unconfirmed)
                {
                    // Single-tenant: an unconfirmed FOREIGN account still
                    // can't rebind outside the relink flow — the email is
                    // the only identity claim the error response carries.
                    if (!relink && Record is { } bound
                        && !bound.Email.Equals(email.Trim(),
                            StringComparison.OrdinalIgnoreCase))
                    {
                        NoteFailure();
                        return AuthResult.Fail(
                            "that isn't the account bound to this install — " +
                            "use Relink to bind a different one");
                    }
                    // GoTrue checks the password BEFORE the confirm gate —
                    // this response proves the credentials are right; it
                    // just withheld the session. Bind the verifier locally
                    // and unlock (no tokens — a real session lands on the
                    // first post-confirmation sign-in).
                    NoteSuccess();
                    lock (_sync)
                    {
                        AccountRecord? prev = _record;
                        _record = AccountRecord.Create(
                            _record?.UserId ?? "unknown",
                            email.Trim(), password);
                        try { PersistLocked(); }
                        catch (Exception ex)
                        {
                            _record = prev;
                            return AuthResult.Fail(
                                $"account record save failed: {ex.Message}");
                        }
                        _unlocked = true;
                    }
                    return new AuthResult(true,
                        "Signed in — email isn't verified yet, so this session " +
                        "runs on the local verifier until you confirm it.",
                        Offline: true);
                }
                NoteFailure();
                return AuthResult.Fail(
                    $"Sign-in failed ({(int)resp.StatusCode}): {msg ?? resp.ReasonPhrase}");
            }
            return Establish(root, password, email, relink);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException
            or OperationCanceledException)
        {
            return OfflineOr(email, password);
        }
    }

    /// <summary>
    /// Offline grace: the server can't answer, so the stored verifier does.
    /// Only the record's own email is accepted — the account is single-tenant.
    /// </summary>
    private AuthResult OfflineOr(string email, string password)
    {
        AccountRecord? record = Record;
        if (record != null
            && !record.Email.Equals(email.Trim(), StringComparison.OrdinalIgnoreCase))
            return AuthResult.Fail("That isn't the account linked on this machine.");
        AuthResult r = TryUnlockOffline(password);
        if (!r.Ok)
            return r;
        return r with { Offline = true };
    }

    /// <summary>Refresh the bearer tokens; a rejected refresh ends the session.</summary>
    public async Task<AuthResult> Refresh()
    {
        AuthTokens? tokens;
        lock (_sync) tokens = _tokens;
        if (!Configured || tokens is not { Renewable: true })
            return AuthResult.Fail("no session to refresh");
        try
        {
            using var req = Json(Req(HttpMethod.Post, "/token?grant_type=refresh_token"),
                new { refresh_token = tokens.RefreshToken });
            using HttpResponseMessage resp = await _http.SendAsync(req);
            string body = await resp.Content.ReadAsStringAsync();
            JsonElement root;
            try { root = JsonDocument.Parse(body).RootElement; }
            catch (Exception) { root = default; }

            if (resp.StatusCode == HttpStatusCode.Unauthorized
                || resp.StatusCode == HttpStatusCode.BadRequest)
            {
                // Refresh token dead — the online session is over. The
                // local verifier still covers offline unlock, so
                // _unlocked survives; only when nothing authorizes this
                // run anymore does the session actually end.
                lock (_sync) { _tokens = null; }
                TokenStore.Clear();
                if (!Authorized)
                    SessionEnded?.Invoke();
                return AuthResult.Fail("session expired — sign in again");
            }
            if (!resp.IsSuccessStatusCode)
                return AuthResult.Fail("refresh failed — keeping current session");
            AuthTokens? next = ParseTokens(root);
            if (next == null)
                return AuthResult.Fail("refresh returned no session");
            lock (_sync) { _tokens = next; }
            TokenStore.Save(next);
            return new AuthResult(true, null);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException
            or OperationCanceledException)
        {
            // Network hiccup — keep the session (grace); the next tick retries.
            return AuthResult.Fail("offline — keeping session");
        }
    }

    /// <summary>Send the recovery email — always Ok-shaped so it can't probe accounts.</summary>
    public async Task<AuthResult> SendRecovery(string email)
    {
        if (!Configured)
            return AuthResult.Fail("Supabase isn't configured (supabase.json).");
        try
        {
            using var req = Json(Req(HttpMethod.Post, "/recover"), new { email });
            using HttpResponseMessage resp = await _http.SendAsync(req);
            if (!resp.IsSuccessStatusCode)
            {
                string body = await resp.Content.ReadAsStringAsync();
                string? msg = null;
                try { msg = ErrorMessage(JsonDocument.Parse(body).RootElement); }
                catch (Exception) { }
                return AuthResult.Fail($"Recovery failed ({(int)resp.StatusCode}): " +
                    (msg ?? resp.ReasonPhrase));
            }
            return new AuthResult(true, null);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException
            or OperationCanceledException)
        {
            return AuthResult.Fail("Couldn't reach the server — try again online.");
        }
    }

    /// <summary>
    /// Finish an emailed reset: verify the deep-link token, set the new
    /// password, re-derive the local verifier. The caller enforces "key
    /// present" — the record write must re-attest on the next key verify.
    /// </summary>
    public async Task<AuthResult> CompleteRecovery(string tokenHash, string newPassword)
    {
        if (!Configured)
            return AuthResult.Fail("Supabase isn't configured (supabase.json).");
        try
        {
            using var req = Json(Req(HttpMethod.Post, "/verify"),
                new { type = "recovery", token_hash = tokenHash });
            using HttpResponseMessage resp = await _http.SendAsync(req);
            string body = await resp.Content.ReadAsStringAsync();
            JsonElement root;
            try { root = JsonDocument.Parse(body).RootElement; }
            catch (Exception) { return AuthResult.Fail("reset link unreadable"); }

            if (!resp.IsSuccessStatusCode)
                return AuthResult.Fail($"Reset link rejected: " +
                    (ErrorMessage(root) ?? "expired or already used"));
            AuthTokens? tokens = ParseTokens(root);
            var user = ParseUser(root);
            if (tokens == null || user == null)
                return AuthResult.Fail("reset link returned no session");

            using var put = Json(Req(HttpMethod.Put, "/user"), new { password = newPassword });
            put.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
            using HttpResponseMessage putResp = await _http.SendAsync(put);
            if (!putResp.IsSuccessStatusCode)
                return AuthResult.Fail($"password update failed ({(int)putResp.StatusCode})");

            lock (_sync)
            {
                AccountRecord? prev = _record;
                _record = AccountRecord.Create(user.Value.Id, user.Value.Email, newPassword);
                try { PersistLocked(); }
                catch (Exception ex)
                {
                    _record = prev;
                    return AuthResult.Fail($"account record save failed: {ex.Message}");
                }
                // Key-fenced write = sanctioned heal (see Establish).
                if (!_attestationClean)
                    _attestationClean = true;
                _tokens = tokens;
                TokenStore.Save(tokens);
                _unlocked = true;
            }
            NoteSuccess();
            return new AuthResult(true, null);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException
            or OperationCanceledException)
        {
            return AuthResult.Fail("Couldn't reach the server — reset needs a connection.");
        }
    }

    /// <summary>
    /// Change the password while signed in: verify the current password
    /// locally first, PUT /user, then re-derive the verifier (the caller
    /// needs the key present — the record write must re-attest).
    /// </summary>
    public async Task<AuthResult> ChangePassword(string current, string newPassword)
    {
        if (!Authorized)
            return AuthResult.Fail("sign in first");
        if (Record?.VerifyPassword(current) != true)
            return AuthResult.Fail("current password is wrong");
        if (!Configured)
            return AuthResult.Fail("Supabase isn't configured (supabase.json).");

        AuthedResult send = await AuthedSend(() =>
            Json(Req(HttpMethod.Put, "/user"), new { password = newPassword }));
        if (!send.Ok)
            return AuthResult.Fail(send.Error!);

        lock (_sync)
        {
            _record!.RewriteVerifier(newPassword);
            try { PersistLocked(); }
            catch (Exception ex)
            {
                return AuthResult.Fail($"account record save failed: {ex.Message}");
            }
        }
        return new AuthResult(true, null);
    }

    /// <summary>
    /// The session ended — sign-out, dead refresh token, etc. The shell
    /// hooks this to close the dashboard/flyout/wizard: an open window
    /// must not keep mutating after its authorization died.
    /// </summary>
    public event Action? SessionEnded;

    /// <summary>Best-effort remote logout; the local session always ends.</summary>
    public async Task<AuthResult> SignOut()
    {
        AuthTokens? tokens;
        lock (_sync) { tokens = _tokens; _tokens = null; _unlocked = false; }
        TokenStore.Clear();
        SessionEnded?.Invoke();
        if (Configured && tokens?.AccessToken is { Length: > 0 } access)
        {
            try
            {
                using var req = Req(HttpMethod.Post, "/logout");
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", access);
                using var resp = await _http.SendAsync(req);
            }
            catch (Exception) { /* remote sign-out is best-effort */ }
        }
        return new AuthResult(true, null);
    }

    /// <summary>
    /// Bearer call with one refresh-and-retry on 401 — the token-expiry path
    /// every authed request shares.
    /// </summary>
    private async Task<AuthedResult> AuthedSend(Func<HttpRequestMessage> make)
    {
        for (int attempt = 0; attempt < 2; attempt++)
        {
            AuthTokens? tokens;
            lock (_sync) tokens = _tokens;
            if (tokens is not { Renewable: true })
                return AuthedResult.Fail("AUTH_REQUIRED");
            using HttpRequestMessage req = make();
            req.Headers.Authorization =
                new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
            HttpResponseMessage resp;
            string body;
            try
            {
                resp = await _http.SendAsync(req);
                body = await resp.Content.ReadAsStringAsync();
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException
                or OperationCanceledException)
            {
                return AuthedResult.Fail("unreachable");
            }
            using (resp)
            {
                if (resp.StatusCode == HttpStatusCode.Unauthorized)
                {
                    // Dead access token — refresh once, then retry the send.
                    if (attempt == 0 && (await Refresh()).Ok)
                        continue;
                    return AuthedResult.Fail("AUTH_REQUIRED");
                }
                JsonElement root = default;
                try { root = JsonDocument.Parse(body).RootElement; }
                catch (Exception) { }
                if (!resp.IsSuccessStatusCode)
                    return AuthedResult.Fail(
                        root.ValueKind == JsonValueKind.Object && ErrorMessage(root) is string m
                            ? m : $"request failed ({(int)resp.StatusCode})");
                return new AuthedResult(true, null, root);
            }
        }
        return AuthedResult.Fail("AUTH_REQUIRED");
    }

    private sealed record AuthedResult(bool Ok, string? Error, JsonElement Root)
    {
        public static AuthedResult Fail(string e) => new(false, e, default);
    }

    /// <summary>
    /// The hourly-refresh tick the engine calls from its slow loop: renews
    /// expiring access tokens so a long-running session doesn't lapse.
    /// Network failure keeps the session (grace); a rejected refresh
    /// reverts to the locked state.
    /// </summary>
    public void TickRefresh()
    {
        bool due;
        lock (_sync)
            due = !_refreshing && _tokens is { Renewable: true }
                  && _tokens.ExpiresAtUtc - DateTime.UtcNow < TimeSpan.FromMinutes(10);
        if (!due)
            return;
        lock (_sync) _refreshing = true;
        _ = Task.Run(async () =>
        {
            try { await Refresh(); }
            finally { lock (_sync) _refreshing = false; }
        });
    }

    // ---------------------------------------------------------- pending staging

    /// <summary>Pre-enrollment record staging — account.pending.json.</summary>
    internal static class PendingStore
    {
        public static string Path =>
            System.IO.Path.Combine(ConfigStore.ConfigDir, "account.pending.json");

        public static bool Exists => File.Exists(Path);

        public static AccountRecord? Load()
        {
            try
            {
                if (!File.Exists(Path))
                    return null;
                return JsonSerializer.Deserialize<AccountRecord>(File.ReadAllText(Path));
            }
            catch (Exception)
            {
                return null;
            }
        }

        public static void Save(AccountRecord? record)
        {
            if (record == null)
            {
                Clear();
                return;
            }
            Directory.CreateDirectory(ConfigStore.ConfigDir);
            AtomicFile.WriteAllText(Path, JsonSerializer.Serialize(record));
        }

        public static void Clear()
        {
            try { File.Delete(Path); }
            catch (Exception) { }
        }
    }
}
