using System.Net;
using System.Text;
using System.Text.Json;
using Xunit;

namespace CryptoKey.Tests;

/// <summary>
/// The account layer's pure invariants: the local PBKDF2 verifier, the
/// pending-record fold, the attestation canonical forms, the GoTrue REST
/// client against a scripted handler, and the IPC gate — all without a
/// network or a real Supabase project.
/// </summary>
public class AuthTests : IDisposable
{
    private static readonly SupabaseConfig Cfg = new()
    {
        ProjectUrl = "https://test.supabase.co",
        AnonKey = "test-anon-key-0123456789abcdef",
    };

    public AuthTests()
    {
        // Every test starts from a clean account slate — session.dat and
        // account.pending.json live in the redirected test config dir.
        AuthService.SetCurrent(null);
        TokenStore.Clear();
        AuthService.PendingStore.Clear();
        ThrottleStore.Clear(); // L6 — persisted throttles must not leak
    }

    public void Dispose()
    {
        AuthService.SetCurrent(null);
        TokenStore.Clear();
        AuthService.PendingStore.Clear();
        ThrottleStore.Clear();
    }

    /// <summary>A queued-response HttpMessageHandler for the REST flows.</summary>
    private sealed class ScriptHandler : HttpMessageHandler
    {
        private readonly Queue<(HttpStatusCode Code, string Body)> _responses = new();
        private readonly Func<HttpRequestMessage, (HttpStatusCode, string)?>? _router;
        public List<string> Requests { get; } = new();
        public bool Unreachable;

        public ScriptHandler() { }
        public ScriptHandler(Func<HttpRequestMessage, (HttpStatusCode, string)?> router)
            => _router = router;

        public void Enqueue(HttpStatusCode code, string body)
            => _responses.Enqueue((code, body));

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (Unreachable)
                throw new HttpRequestException("scripted outage");
            string body = request.Content?.ReadAsStringAsync().Result ?? "";
            Requests.Add($"{request.Method} {request.RequestUri} {body}");
            var r = _router?.Invoke(request)
                ?? (_responses.Count > 0 ? _responses.Dequeue()
                    : (HttpStatusCode.InternalServerError, "{}"));
            return Task.FromResult(new HttpResponseMessage(r.Item1)
            {
                Content = new StringContent(r.Item2, Encoding.UTF8, "application/json"),
            });
        }
    }

    private static string TokenJson(string access = "acc-1", string refresh = "ref-1",
        string id = "user-1", string email = "a@b.c", int expiresIn = 3600)
        => JsonSerializer.Serialize(new
        {
            access_token = access,
            refresh_token = refresh,
            expires_in = expiresIn,
            user = new { id, email },
        });

    // ---------------------------------------------------------- verifier

    [Fact]
    public void Verifier_round_trips_and_rejects()
    {
        AccountRecord rec = AccountRecord.Create("u1", "a@b.c", "correct horse");
        Assert.True(rec.IsComplete);
        Assert.True(rec.VerifyPassword("correct horse"));
        Assert.False(rec.VerifyPassword("wrong"));
        Assert.False(rec.VerifyPassword(""));
    }

    [Fact]
    public void Verifier_malformed_fields_fail_closed_not_throw()
    {
        var rec = new AccountRecord
        {
            UserId = "u", Email = "a@b.c",
            VerifierSalt = "!!!not-base64!!!", VerifierHash = "%%%",
            VerifierIterations = 600_000,
        };
        // IsComplete checks presence, not validity — but verify must still
        // fail closed on undecodable fields, never throw.
        Assert.False(rec.VerifyPassword("x"));

        var empty = new AccountRecord { UserId = "u" };
        Assert.False(empty.IsComplete);
        Assert.False(empty.VerifyPassword("x"));

        AccountRecord good = AccountRecord.Create("u", "a@b.c", "x");
        good.VerifierSalt = Convert.ToBase64String(new byte[8]); // wrong len
        Assert.False(good.VerifyPassword("x"));
    }

    [Fact]
    public void RewriteVerifier_rebinds_to_the_new_password()
    {
        AccountRecord rec = AccountRecord.Create("u1", "a@b.c", "old-pw");
        rec.RewriteVerifier("new-pw");
        Assert.False(rec.VerifyPassword("old-pw"));
        Assert.True(rec.VerifyPassword("new-pw"));
    }

    // ---------------------------------------------------------- pending fold

    [Fact]
    public void Pending_record_folds_into_enrollment()
    {
        // A prior test's config could already carry an account — the fold
        // prefers Existing over pending, so clear ALL three copies (primary
        // + file backup + third copy) — Load() restores a missing primary
        // from the backups, which is itself under test elsewhere.
        File.Delete(ConfigStore.ConfigPath);
        File.Delete(ConfigStore.ConfigPath + ".bak");
        File.Delete(TestInit.ThirdCopyPath);
        Assert.Null(ConfigStore.Load()?.Account);
        AccountRecord pending = AccountRecord.Create("u1", "a@b.c", "pw");
        AuthService.PendingStore.Save(pending);
        Assert.True(AuthService.PendingStore.Exists);

        string dir = TestDisk.TempDir();
        var flow = new EnrollmentFlow();
        flow.SelectDisk(TestDisk.For(dir));
        flow.Confirm(flow.Phrase!);

        EnrollResult r = flow.Commit();
        Assert.True(r.Ok, r.Message);
        Assert.NotNull(r.Config!.Account);
        Assert.Equal("a@b.c", r.Config.Account!.Email);
        Assert.False(AuthService.PendingStore.Exists); // staging file served its purpose

        KeyConfig? saved = ConfigStore.Load();
        Assert.Equal(pending.VerifierHash, saved?.Account?.VerifierHash);
        // The keyfile's attestation covers the account from the start.
        KeyfileCheck check = KeyVerifier.Check(r.Config, TestDisk.For(dir));
        Assert.Equal(AttestState.Ok, check.Attest);
    }

    [Fact]
    public void Reenroll_carries_the_bound_account_forward()
    {
        string dir = TestDisk.TempDir();
        var flow = new EnrollmentFlow();
        flow.SelectDisk(TestDisk.For(dir));
        flow.Confirm(flow.Phrase!);
        EnrollResult first = flow.Commit();
        Assert.True(first.Ok, first.Message);
        first.Config!.Account = AccountRecord.Create("u1", "a@b.c", "pw");
        ConfigStore.Save(first.Config);

        var again = new EnrollmentFlow(); // picks up Existing with the account
        again.SelectDisk(TestDisk.For(dir));
        again.Confirm(again.Phrase!);
        EnrollResult second = again.Commit();
        Assert.True(second.Ok, second.Message);
        Assert.Equal("a@b.c", second.Config!.Account!.Email);
    }

    // ---------------------------------------------------------- attestation

    [Fact]
    public void Account_free_config_accepts_all_historical_forms()
    {
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig cfg = TestDisk.NewConfig(secret);
        cfg.Account = null;
        cfg.V2Only = false; // pre-latch install — the historical forms apply

        // Current canon, no epoch, no accounthash, legacy — all still pass.
        Assert.True(ConfigStore.AttestMatches(secret, cfg,
            ConfigStore.ComputeAttest(secret, cfg)));
        Assert.True(ConfigStore.AttestMatches(secret, cfg,
            ConfigStore.ComputeAttestNoEpoch(secret, cfg)));

        // …and the latch: once v2-only sets, the pre-latch canons stop
        // matching — an off-app v2only:false flip can't hide behind them.
        cfg.V2Only = true;
        Assert.False(ConfigStore.AttestMatches(secret, cfg,
            ConfigStore.ComputeAttestNoEpoch(secret, cfg)));
    }

    [Fact]
    public void Account_bound_config_verifies_and_rejects_graft()
    {
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig cfg = TestDisk.NewConfig(secret);
        cfg.Account = AccountRecord.Create("u1", "a@b.c", "pw");

        byte[] stored = ConfigStore.ComputeAttest(secret, cfg);
        Assert.True(ConfigStore.AttestMatches(secret, cfg, stored));

        // Grafted verifier hash — same slot, attacker's password — must
        // fail even though the legacy forms are computed too.
        cfg.Account!.VerifierHash =
            Convert.ToBase64String(TestDisk.RandomSecret()[..32]);
        Assert.False(ConfigStore.AttestMatches(secret, cfg, stored));

        // And the strict rule: while an account is bound, a MAC over the
        // pre-account canon is NOT accepted — deleting/grafting the section
        // can't hide behind a legacy form.
        cfg.Account.VerifierHash =
            AccountRecord.Create("u1", "a@b.c", "pw").VerifierHash;
        byte[] accountFreeCanon = ConfigStore.ComputeAttestNoEpoch(secret, cfg);
        Assert.False(ConfigStore.AttestMatches(secret, cfg, accountFreeCanon));
    }

    [Fact]
    public void Keyfile_attestation_flags_a_tampered_verifier()
    {
        byte[] secret = TestDisk.RandomSecret();
        string dir = TestDisk.TempDir();
        KeyConfig cfg = TestDisk.NewConfig(secret);
        cfg.Account = AccountRecord.Create("u1", "a@b.c", "pw");
        TestDisk.WriteKeyfile(dir, secret, cfg);

        Assert.Equal(AttestState.Ok,
            KeyVerifier.Check(cfg, TestDisk.For(dir)).Attest);

        cfg.Account!.VerifierHash =
            Convert.ToBase64String(TestDisk.RandomSecret()[..32]);
        Assert.Equal(AttestState.Mismatch,
            KeyVerifier.Check(cfg, TestDisk.For(dir)).Attest);
    }

    // ---------------------------------------------------------- AuthService REST

    [Fact]
    public async Task Signup_with_session_tokens_establishes_record()
    {
        var handler = new ScriptHandler();
        handler.Enqueue(HttpStatusCode.OK, TokenJson());
        var auth = new AuthService(Cfg, handler);
        AuthService.SetCurrent(auth);

        AuthResult r = await auth.SignUp("a@b.c", "pw-123456");
        Assert.True(r.Ok, r.Error);
        Assert.Equal(AuthGateState.Online, auth.State);
        Assert.True(auth.Authorized);
        Assert.True(auth.Record?.VerifyPassword("pw-123456"));
        Assert.Contains("/auth/v1/signup", handler.Requests[0]);
        Assert.True(TokenStore.Exists);
    }

    [Fact]
    public async Task Signup_email_confirm_returns_needs_confirm()
    {
        var handler = new ScriptHandler();
        // Confirm-on signup returns the user object, no tokens.
        handler.Enqueue(HttpStatusCode.OK,
            JsonSerializer.Serialize(new { id = "u9", email = "a@b.c" }));
        var auth = new AuthService(Cfg, handler);
        AuthService.SetCurrent(auth);

        AuthResult r = await auth.SignUp("a@b.c", "pw-123456");
        Assert.True(r.Ok);
        Assert.True(r.NeedsConfirm);
        Assert.False(auth.Authorized);
    }

    [Fact]
    public async Task Signin_online_then_offline_grace_unlocks()
    {
        var handler = new ScriptHandler();
        handler.Enqueue(HttpStatusCode.OK, TokenJson());
        var auth = new AuthService(Cfg, handler);
        AuthService.SetCurrent(auth);

        Assert.True((await auth.SignIn("a@b.c", "pw-123456")).Ok);

        // New process-day: the record survives in pending storage, but the
        // session file is gone (expired tokens cleared) and the server is
        // unreachable — the verifier is the only way back in.
        TokenStore.Clear();
        var auth2 = new AuthService(Cfg, new ScriptHandler { Unreachable = true });
        auth2.BindConfig(null);
        Assert.Equal(AuthGateState.Locked, auth2.State);

        AuthResult r = await auth2.SignIn("a@b.c", "pw-123456");
        Assert.True(r.Ok, r.Error);
        Assert.True(r.Offline);
        Assert.Equal(AuthGateState.OfflineUnlocked, auth2.State);
    }

    [Fact]
    public async Task Unverified_email_signin_binds_the_verifier_locally()
    {
        // email_not_confirmed only fires after GoTrue checked the password —
        // it's proof of credentials with a withheld session, not a failure.
        var handler = new ScriptHandler();
        handler.Enqueue(HttpStatusCode.BadRequest,
            """{"error_code":"email_not_confirmed","msg":"Email not confirmed"}""");
        var auth = new AuthService(Cfg, handler);
        AuthService.SetCurrent(auth);

        AuthResult r = await auth.SignIn("a@b.c", "pw-123456");
        Assert.True(r.Ok, r.Error);
        Assert.True(r.Offline);
        Assert.True(auth.Authorized);
        Assert.Equal(AuthGateState.OfflineUnlocked, auth.State);

        // The record it wrote verifies the same password — and a later
        // confirmed sign-in upgrades it to a real session.
        handler.Enqueue(HttpStatusCode.OK, TokenJson());
        Assert.True((await auth.SignIn("a@b.c", "pw-123456")).Ok);
        Assert.Equal(AuthGateState.Online, auth.State);
    }

    [Fact]
    public async Task Foreign_signin_is_refused_on_a_bound_install()
    {
        // Bound to user-1…
        var handler = new ScriptHandler();
        handler.Enqueue(HttpStatusCode.OK, TokenJson(id: "user-1"));
        var auth = new AuthService(Cfg, handler);
        AuthService.SetCurrent(auth);
        Assert.True((await auth.SignIn("a@b.c", "pw-123456")).Ok);
        string boundHash = auth.Record!.VerifierHash;

        // …a DIFFERENT account's valid sign-in must not silently rebind
        // the verifier — else the foreign password would gate this box.
        handler.Enqueue(HttpStatusCode.OK, TokenJson(id: "user-2", email: "x@y.z"));
        AuthResult r = await auth.SignIn("x@y.z", "other-pw");
        Assert.False(r.Ok);
        Assert.Equal(boundHash, auth.Record!.VerifierHash); // still bound to user-1's verifier

        // The key-fenced relink path is the sanctioned escape.
        handler.Enqueue(HttpStatusCode.OK, TokenJson(id: "user-2", email: "x@y.z"));
        r = await auth.SignIn("x@y.z", "other-pw", relink: true);
        Assert.True(r.Ok, r.Error);
        Assert.Equal("user-2", auth.Record!.UserId);
    }

    [Fact]
    public async Task Unconfirmed_foreign_signin_is_also_refused()
    {
        var handler = new ScriptHandler();
        handler.Enqueue(HttpStatusCode.OK, TokenJson(id: "user-1"));
        var auth = new AuthService(Cfg, handler);
        AuthService.SetCurrent(auth);
        Assert.True((await auth.SignIn("a@b.c", "pw-123456")).Ok);
        string boundHash = auth.Record!.VerifierHash;

        // The email_not_confirmed proof-of-credentials path carries no user
        // id — the email claim is checked against the bound record instead.
        handler.Enqueue(HttpStatusCode.BadRequest,
            """{"error_code":"email_not_confirmed","msg":"Email not confirmed"}""");
        AuthResult r = await auth.SignIn("foreign@x.y", "their-pw");
        Assert.False(r.Ok);
        Assert.Equal(boundHash, auth.Record!.VerifierHash);
    }

    [Fact]
    public async Task Dirty_attestation_locks_every_path_until_relink()
    {
        // A grafted/edited account record sets _attestationClean=false on
        // the next key verify (engine side). While dirty, NOTHING may
        // authorize — not the offline verifier, not a live online sign-in,
        // not a previously-armed session.
        var handler = new ScriptHandler();
        handler.Enqueue(HttpStatusCode.OK, TokenJson());
        var auth = new AuthService(Cfg, handler);
        AuthService.SetCurrent(auth);
        Assert.True((await auth.SignIn("a@b.c", "pw-123456")).Ok);
        Assert.True(auth.Authorized);

        auth.SetAttestationClean(false); // what the engine does on a Mismatch
        Assert.False(auth.Authorized);   // live session no longer counts
        Assert.False(auth.TryUnlockOffline("pw-123456").Ok);
        Assert.False(auth.Authorize("pw-123456", out _));

        // Online sign-in is refused too — the graft could be laundering.
        handler.Enqueue(HttpStatusCode.OK, TokenJson());
        Assert.False((await auth.SignIn("a@b.c", "pw-123456")).Ok);
        Assert.False(auth.Authorized);

        // The key-fenced relink path is the way back — and the write it
        // performs IS the heal, so the flag lifts on success.
        handler.Enqueue(HttpStatusCode.OK, TokenJson());
        Assert.True((await auth.SignIn("a@b.c", "pw-123456", relink: true)).Ok);
        Assert.True(auth.Authorized);
    }

    [Fact]
    public async Task Signout_and_dead_refresh_end_the_session_event()
    {
        var handler = new ScriptHandler();
        handler.Enqueue(HttpStatusCode.OK, TokenJson());
        var auth = new AuthService(Cfg, handler);
        int ended = 0;
        auth.SessionEnded += () => ended++;

        Assert.True((await auth.SignIn("a@b.c", "pw-123456")).Ok);
        Assert.Equal(0, ended);
        await auth.SignOut();
        Assert.Equal(1, ended);
        Assert.False(auth.Authorized);

        // A rejected refresh does NOT end the session while the offline
        // verifier still authorizes the run (documented offline grace).
        // The expired access token makes Refresh actually post.
        handler.Enqueue(HttpStatusCode.OK, TokenJson(access: "dead", expiresIn: -1));
        Assert.True((await auth.SignIn("a@b.c", "pw-123456")).Ok);
        handler.Enqueue(HttpStatusCode.BadRequest, """{"error":"invalid_grant"}""");
        Assert.False((await auth.Refresh()).Ok);
        Assert.Equal(1, ended);          // verifier still covers — session lives
        Assert.True(auth.Authorized);

        // ...but with the attestation dirty, a dead refresh leaves nothing
        // authorized — now the session truly ends.
        auth.SetAttestationClean(false);
        handler.Enqueue(HttpStatusCode.OK, TokenJson(id: "user-1"));
        Assert.True((await auth.SignIn("a@b.c", "pw-123456", relink: true)).Ok);
        auth.SetAttestationClean(false); // dirty again post-relink
        handler.Enqueue(HttpStatusCode.BadRequest, """{"error":"invalid_grant"}""");
        Assert.False((await auth.Refresh()).Ok);
        Assert.Equal(2, ended);
        Assert.False(auth.Authorized);
    }

    [Fact]
    public async Task Offline_unlock_before_any_signin_is_refused()
    {
        var auth = new AuthService(Cfg, new ScriptHandler());
        auth.BindConfig(null);
        AuthResult r = await auth.SignIn("a@b.c", "pw");
        Assert.False(r.Ok); // no record — nothing to verify against
        Assert.Equal(AuthGateState.Unenrolled, auth.State);
    }

    [Fact]
    public async Task Refresh_renews_and_a_rejected_refresh_ends_the_session()
    {
        var handler = new ScriptHandler();
        handler.Enqueue(HttpStatusCode.OK, TokenJson());
        var auth = new AuthService(Cfg, handler);
        AuthService.SetCurrent(auth);
        Assert.True((await auth.SignIn("a@b.c", "pw")).Ok);

        handler.Enqueue(HttpStatusCode.OK, TokenJson(access: "acc-2", refresh: "ref-2"));
        Assert.True((await auth.Refresh()).Ok);
        Assert.Contains("grant_type=refresh_token", handler.Requests[^1]);

        handler.Enqueue(HttpStatusCode.BadRequest, """{"error":"invalid_grant"}""");
        Assert.False((await auth.Refresh()).Ok);
        Assert.False(TokenStore.Exists); // dead session cleared
    }

    [Fact]
    public async Task SendRecovery_is_ok_shaped_and_reaches_recover()
    {
        var handler = new ScriptHandler();
        handler.Enqueue(HttpStatusCode.OK, "{}");
        var auth = new AuthService(Cfg, handler);

        AuthResult r = await auth.SendRecovery("a@b.c");
        Assert.True(r.Ok, r.Error);
        Assert.Contains("/auth/v1/recover", handler.Requests[0]);
    }

    [Fact]
    public async Task CompleteRecovery_verifies_token_puts_password_and_rewrites_verifier()
    {
        var handler = new ScriptHandler();
        handler.Enqueue(HttpStatusCode.OK, TokenJson());   // /verify
        handler.Enqueue(HttpStatusCode.OK, "{}");          // PUT /user
        var auth = new AuthService(Cfg, handler);
        AuthService.SetCurrent(auth);

        AuthResult r = await auth.CompleteRecovery("tok-hash", "new-pw");
        Assert.True(r.Ok, r.Error);
        Assert.Contains("/auth/v1/verify", handler.Requests[0]);
        Assert.Contains("/auth/v1/user", handler.Requests[1]);
        Assert.True(auth.Record?.VerifyPassword("new-pw"));
    }

    [Fact]
    public async Task CompleteRecovery_refuses_a_foreign_account()
    {
        // M2 — a cryptokey://recover link fired by any web page must not
        // rebind this install to a different account. The /verify response
        // names the token's user; mismatch with the bound record → refuse
        // BEFORE the password write goes out.
        var handler = new ScriptHandler();
        var auth = new AuthService(Cfg, handler);
        KeyConfig cfg = TestDisk.NewConfig(TestDisk.RandomSecret());
        cfg.Account = AccountRecord.Create("user-1", "a@b.c", "acct-pw");
        auth.BindConfig(cfg);
        AuthService.SetCurrent(auth);

        handler.Enqueue(HttpStatusCode.OK, TokenJson(id: "user-2", email: "x@y.z"));
        AuthResult r = await auth.CompleteRecovery("tok-hash", "new-pw");

        Assert.False(r.Ok);
        Assert.Contains("different account", r.Error);
        Assert.Single(handler.Requests); // /verify ran, PUT /user never did
        Assert.Equal("user-1", auth.Record!.UserId); // still bound
    }

    [Fact]
    public async Task CompleteRecovery_same_user_rebinds_fine()
    {
        var handler = new ScriptHandler();
        handler.Enqueue(HttpStatusCode.OK, TokenJson(id: "user-1"));
        handler.Enqueue(HttpStatusCode.OK, "{}");
        var auth = new AuthService(Cfg, handler);
        KeyConfig cfg = TestDisk.NewConfig(TestDisk.RandomSecret());
        cfg.Account = AccountRecord.Create("user-1", "a@b.c", "acct-pw");
        auth.BindConfig(cfg);
        AuthService.SetCurrent(auth);

        Assert.True((await auth.CompleteRecovery("tok-hash", "new-pw")).Ok);
        Assert.True(auth.Record!.VerifyPassword("new-pw"));
    }

    [Fact]
    public async Task Unconfigured_service_fails_clearly()
    {
        var auth = new AuthService(null, null); // no supabase.json
        Assert.False(auth.Configured);
        Assert.False((await auth.SignUp("a@b.c", "pw")).Ok);
        Assert.False((await auth.SendRecovery("a@b.c")).Ok);
    }

    // ---------------------------------------------------------- IPC gate

    [Fact]
    public void Gated_verbs_require_auth_when_an_account_is_bound()
    {
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig cfg = TestDisk.NewConfig(secret);
        cfg.Account = AccountRecord.Create("u1", "a@b.c", "acct-pw");
        AuthService.SetCurrent(new AuthService(Cfg, new ScriptHandler()));
        using var svc = new GuardService(cfg, devMode: false, forceClassic: false);

        // Mutating verbs gated…
        Assert.StartsWith("err AUTH_REQUIRED", svc.DispatchCommand("pause"));
        Assert.StartsWith("err AUTH_REQUIRED", svc.DispatchCommand("resume"));
        Assert.StartsWith("err AUTH_REQUIRED", svc.DispatchCommand("quit"));
        Assert.StartsWith("err AUTH_REQUIRED", svc.DispatchCommand("vault mount"));

        // …open verbs stay open — lock only makes the box safer.
        Assert.StartsWith("ok", svc.DispatchCommand("status"));
        Assert.StartsWith("ok", svc.DispatchCommand("auth status"));
        Assert.StartsWith("ok", svc.DispatchCommand("vault status"));

        // The password trailer unlocks the session (b64 — punctuation-safe).
        string trailer = " |auth " + Convert.ToBase64String(
            Encoding.UTF8.GetBytes("acct-pw"));
        Assert.StartsWith("ok", svc.DispatchCommand("pause 1" + trailer));
        // And now the session is armed — no trailer needed.
        Assert.StartsWith("ok", svc.DispatchCommand("resume"));
    }

    [Fact]
    public void No_account_means_no_gate()
    {
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig cfg = TestDisk.NewConfig(secret);
        cfg.Account = null;
        AuthService.SetCurrent(new AuthService(Cfg, new ScriptHandler()));
        using var svc = new GuardService(cfg, devMode: false, forceClassic: false);

        Assert.StartsWith("ok", svc.DispatchCommand("pause 1"));
        Assert.StartsWith("ok", svc.DispatchCommand("resume"));
    }

    [Fact]
    public void Wrong_password_is_refused_and_the_right_one_arms()
    {
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig cfg = TestDisk.NewConfig(secret);
        cfg.Account = AccountRecord.Create("u1", "a@b.c", "real-pw");
        AuthService.SetCurrent(new AuthService(Cfg, new ScriptHandler()));
        using var svc = new GuardService(cfg, devMode: false, forceClassic: false);

        string bad = " |auth " + Convert.ToBase64String(
            Encoding.UTF8.GetBytes("nope"));
        Assert.StartsWith("err wrong account password",
            svc.DispatchCommand("pause" + bad));

        string good = " |auth " + Convert.ToBase64String(
            Encoding.UTF8.GetBytes("real-pw"));
        Assert.StartsWith("ok", svc.DispatchCommand("pause 1" + good));
    }

    [Fact]
    public void Malformed_auth_trailer_is_refused()
    {
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig cfg = TestDisk.NewConfig(secret);
        cfg.Account = AccountRecord.Create("u1", "a@b.c", "pw");
        AuthService.SetCurrent(new AuthService(Cfg, new ScriptHandler()));
        using var svc = new GuardService(cfg, devMode: false, forceClassic: false);

        Assert.StartsWith("err malformed auth trailer",
            svc.DispatchCommand("pause |auth !!!notb64!!!"));
    }

    [Fact]
    public void Signout_is_gated_and_the_trailer_authorizes_it()
    {
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig cfg = TestDisk.NewConfig(secret);
        cfg.Account = AccountRecord.Create("u1", "a@b.c", "acct-pw");
        AuthService.SetCurrent(new AuthService(Cfg, new ScriptHandler()));
        using var svc = new GuardService(cfg, devMode: false, forceClassic: false);

        // signout is a mutator like the rest: no session → AUTH_REQUIRED,
        // and the trailer arms it inline.
        Assert.StartsWith("err AUTH_REQUIRED", svc.DispatchCommand("auth signout"));
        string trailer = " |auth " + Convert.ToBase64String(
            Encoding.UTF8.GetBytes("acct-pw"));
        Assert.StartsWith("ok", svc.DispatchCommand("auth signout" + trailer));
    }

    [Fact]
    public void Autolock_is_disarmed_without_a_signed_in_session()
    {
        // No account bound at all — nothing to arm with. An UNBOUND install
        // never auto-locks regardless of session machinery.
        KeyConfig cfg = TestDisk.NewConfig(TestDisk.RandomSecret());
        cfg.Guard.Watchdog = false;
        cfg.Guard.UpdateCheckEnabled = false;
        AuthService.SetCurrent(new AuthService(Cfg, new ScriptHandler()));
        using var svc = new GuardService(cfg, devMode: false, forceClassic: false);

        svc.Start(); // no USB enumerated → the startup auto-lock check fires
        Assert.NotEqual(GuardState.Locked, svc.State);

        // …but manual lock never gates — locking is always safe direction.
        Assert.StartsWith("ok", svc.DispatchCommand("lock"));
        Assert.Equal(GuardState.Locked, svc.State);
    }

    [Fact]
    public void Bound_account_stays_armed_with_a_cold_session()
    {
        // THE fail-open fix: a bound account arms auto-lock even with NO
        // session this run — expired tokens, an offline box, or a revoked
        // refresh can't disarm it. (The audit's H1: session-gated arming
        // let cutting the network for an hour switch protection off.)
        KeyConfig cfg = TestDisk.NewConfig(TestDisk.RandomSecret());
        cfg.Account = AccountRecord.Create("u1", "a@b.c", "acct-pw");
        cfg.Guard.Watchdog = false;
        cfg.Guard.UpdateCheckEnabled = false;
        var auth = new AuthService(Cfg, new ScriptHandler());
        AuthService.SetCurrent(auth);
        using var svc = new GuardService(cfg, devMode: false, forceClassic: false);
        Assert.False(auth.SessionLive);   // nobody signed in this run
        Assert.True(auth.ArmedForAutoLock); // …but a bound install is armed

        svc.Start(); // key absent → armed install locks
        Assert.Equal(GuardState.Locked, svc.State);
    }

    [Fact]
    public void Explicit_signout_latches_disarm_and_signin_rearms()
    {
        // The ONLY disarm is a gated `auth signout`: the latch persists in
        // the record (survives restart) until a real sign-in clears it.
        KeyConfig cfg = TestDisk.NewConfig(TestDisk.RandomSecret());
        cfg.Account = AccountRecord.Create("u1", "a@b.c", "acct-pw");
        cfg.Guard.Watchdog = false;
        cfg.Guard.UpdateCheckEnabled = false;
        AuthService.SetCurrent(new AuthService(Cfg, new ScriptHandler()));
        using var svc = new GuardService(cfg, devMode: false, forceClassic: false);

        string trailer = " |auth " + Convert.ToBase64String(
            Encoding.UTF8.GetBytes("acct-pw"));
        Assert.StartsWith("ok", svc.DispatchCommand("auth signout" + trailer));
        Assert.True(cfg.Account.SignedOut);      // latch wrote to the record
        Assert.False(AuthService.Current.ArmedForAutoLock);

        svc.Start(); // key absent + signed out → stays unlocked
        Assert.NotEqual(GuardState.Locked, svc.State);

        string signin = "auth signin " + Convert.ToBase64String(
            Encoding.UTF8.GetBytes("acct-pw"));
        Assert.StartsWith("ok", svc.DispatchCommand(signin));
        Assert.False(cfg.Account.SignedOut);     // a real sign-in re-arms
        Assert.True(AuthService.Current.ArmedForAutoLock);
    }

    [Fact]
    public async Task Online_signin_fires_ArmingChanged_when_it_re_arms()
    {
        // The offline sign-in already announced re-arms via the event;
        // the online paths (Establish / recovery) silently re-armed and
        // nobody logged it. Sign-out alerts must pair with sign-in arms.
        var handler = new ScriptHandler();
        handler.Enqueue(HttpStatusCode.OK, TokenJson());
        handler.Enqueue(HttpStatusCode.NoContent, "{}"); // remote logout
        handler.Enqueue(HttpStatusCode.OK, TokenJson());
        var auth = new AuthService(Cfg, handler);
        KeyConfig cfg = TestDisk.NewConfig(TestDisk.RandomSecret());
        cfg.Account = AccountRecord.Create("user-1", "a@b.c", "pw-123456");
        auth.BindConfig(cfg);
        var events = new List<bool>();
        auth.ArmingChanged += a => events.Add(a);

        Assert.True((await auth.SignIn("a@b.c", "pw-123456")).Ok);
        Assert.Empty(events);                    // armed → armed: no transition
        Assert.True((await auth.SignOut()).Ok);
        Assert.Equal(new[] { false }, events);   // the latch disarmed
        Assert.False(auth.ArmedForAutoLock);
        Assert.True((await auth.SignIn("a@b.c", "pw-123456")).Ok);
        Assert.Equal(new[] { false, true }, events); // sign-in re-arms — and says so
        Assert.True(auth.ArmedForAutoLock);
    }

    [Fact]
    public void Snapshot_reports_autolock_arming_for_the_ui()
    {
        // The dashboard wordmark + tray tooltip read this field — it must
        // mirror ArmedForAutoLock exactly (bound install armed unless the
        // explicit SignedOut latch is persisted).
        KeyConfig cfg = TestDisk.NewConfig(TestDisk.RandomSecret());
        cfg.Account = AccountRecord.Create("u1", "a@b.c", "acct-pw");
        cfg.Guard.Watchdog = false;
        cfg.Guard.UpdateCheckEnabled = false;
        AuthService.SetCurrent(new AuthService(Cfg, new ScriptHandler()));
        using var svc = new GuardService(cfg, devMode: false, forceClassic: false);

        Assert.True(svc.Snapshot().AutoLockArmed);
        cfg.Account.SignedOut = true;
        Assert.False(svc.Snapshot().AutoLockArmed);
    }

    [Fact]
    public void Reenrolled_while_locked_keeps_the_phrase_freeze()
    {
        // The phrase freeze is live-surface state, not config state —
        // `reenrolled` (ungated on an install with no account) must not
        // thaw it: 3 fails → freeze → reenrolled → fresh counter while
        // still locked is a rate-limit bypass.
        KeyConfig cfg = TestDisk.NewConfig(TestDisk.RandomSecret());
        cfg.Guard.Watchdog = false;
        cfg.Guard.UpdateCheckEnabled = false;
        ConfigStore.Save(cfg); // ReloadConfig reads from disk
        AuthService.SetCurrent(new AuthService(Cfg, new ScriptHandler()));
        using var svc = new GuardService(cfg, devMode: false, forceClassic: false);
        svc.Start();
        Assert.StartsWith("ok", svc.DispatchCommand("lock"));

        var surface = TestPlatform.TestLockSurfaceFactory.Last
            ?? throw new InvalidOperationException("no lock surface");
        for (int i = 0; i < 3; i++)
        {
            surface.Submit("AAAAA-BBBBB-CCCCC-DDDDD");
            // PBKDF2 runs off-thread; the result lands via the dispatcher.
            Assert.True(SpinWait.SpinUntil(
                () => surface.FailedAttempts > i, TimeSpan.FromSeconds(10)),
                $"failed attempt #{i + 1} never landed");
        }
        Assert.Equal(3, svc.FailedAttempts);
        Assert.NotNull(surface.CooldownUntil); // the 15s freeze latched

        Assert.StartsWith("ok", svc.DispatchCommand("reenrolled"));

        Assert.Equal(GuardState.Locked, svc.State);
        Assert.Equal(3, svc.FailedAttempts);   // counter survived
        Assert.NotNull(surface.CooldownUntil); // freeze survived
    }

    [Fact]
    public void Signed_in_session_arms_autolock_at_startup()
    {
        KeyConfig cfg = TestDisk.NewConfig(TestDisk.RandomSecret());
        cfg.Account = AccountRecord.Create("u1", "a@b.c", "acct-pw");
        cfg.Guard.Watchdog = false;
        cfg.Guard.UpdateCheckEnabled = false;
        var auth = new AuthService(Cfg, new ScriptHandler());
        AuthService.SetCurrent(auth);
        using var svc = new GuardService(cfg, devMode: false, forceClassic: false);
        // ctor binds the record — the offline verifier can arm the session.
        Assert.True(auth.TryUnlockOffline("acct-pw").Ok);

        svc.Start(); // key absent at startup + live session → locks.
        Assert.Equal(GuardState.Locked, svc.State);
    }
}
