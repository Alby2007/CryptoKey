using System.Net;
using System.Text;
using System.Text.Json;
using Xunit;

namespace CryptoKey.Tests;

/// <summary>
/// M6 — sign-in is a bounded window, not a run-lifetime latch: ordinary
/// gated ops expire with the gate window, destructive ops (unenroll /
/// vault delete / update apply / quit) need the shorter fresh window or
/// an inline password, and LockSession drops the run's authorization
/// without signing out.
/// </summary>
public class SessionWindowTests : IDisposable
{
    private static readonly SupabaseConfig Cfg = new()
    {
        ProjectUrl = "https://test.supabase.co",
        AnonKey = "test-anon-key-0123456789abcdef",
    };

    private static readonly TimeSpan GateWas = AuthService.GateTtl;
    private static readonly TimeSpan FreshWas = AuthService.FreshTtl;

    public SessionWindowTests()
    {
        AuthService.SetCurrent(null);
        TokenStore.Clear();
        AuthService.PendingStore.Clear();
        ThrottleStore.Clear();
    }

    public void Dispose()
    {
        AuthService.GateTtl = GateWas;
        AuthService.FreshTtl = FreshWas;
        AuthService.SetCurrent(null);
        TokenStore.Clear();
        AuthService.PendingStore.Clear();
        ThrottleStore.Clear();
    }

    private sealed class ScriptHandler : HttpMessageHandler
    {
        private readonly Queue<(HttpStatusCode Code, string Body)> _responses = new();
        public void Enqueue(HttpStatusCode code, string body) => _responses.Enqueue((code, body));
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var r = _responses.Count > 0 ? _responses.Dequeue()
                : (HttpStatusCode.InternalServerError, "{}");
            return Task.FromResult(new HttpResponseMessage(r.Item1)
            {
                Content = new StringContent(r.Item2, Encoding.UTF8, "application/json"),
            });
        }
    }

    private static string TokenJson()
        => JsonSerializer.Serialize(new
        {
            access_token = "acc-1",
            refresh_token = "ref-1",
            expires_in = 3600,
            user = new { id = "user-1", email = "a@b.c" },
        });

    private static KeyConfig BoundConfig(string pw)
    {
        KeyConfig cfg = TestDisk.NewConfig(TestDisk.RandomSecret());
        cfg.Account = AccountRecord.Create("u1", "a@b.c", pw);
        cfg.Guard.Watchdog = false;
        cfg.Guard.UpdateCheckEnabled = false;
        return cfg;
    }

    [Fact]
    public void Password_grant_expires_with_the_gate_window()
    {
        KeyConfig cfg = BoundConfig("acct-pw");
        var auth = new AuthService(Cfg, new ScriptHandler());
        auth.BindConfig(cfg);

        AuthService.GateTtl = TimeSpan.FromMilliseconds(60);
        Assert.True(auth.Authorize("acct-pw", out _));
        Assert.True(auth.Authorize(null, out _));      // window open

        Thread.Sleep(120);
        Assert.False(auth.Authorize(null, out string err));
        Assert.Equal("AUTH_REQUIRED", err);
        Assert.False(auth.SessionLive);              // display agrees
    }

    [Fact]
    public void Fresh_window_bounds_destructive_verbs_only()
    {
        KeyConfig cfg = BoundConfig("acct-pw");
        var auth = new AuthService(Cfg, new ScriptHandler());
        AuthService.SetCurrent(auth);
        using var svc = new GuardService(cfg, devMode: false, forceClassic: false);

        AuthService.GateTtl = TimeSpan.FromSeconds(30);
        AuthService.FreshTtl = TimeSpan.FromMilliseconds(60);

        string trailer = " |auth " + Convert.ToBase64String(
            Encoding.UTF8.GetBytes("acct-pw"));
        // Grant: pause succeeds inline. The install stays Paused for the
        // rest of the test — resuming an armed box re-locks instantly.
        Assert.StartsWith("ok", svc.DispatchCommand("pause 5" + trailer));

        Thread.Sleep(150);
        // Fresh window closed, gate window still open: destructive verbs
        // reprompt…
        Assert.Contains("AUTH_REQUIRED", svc.DispatchCommand("unenroll"));
        Assert.Contains("AUTH_REQUIRED", svc.DispatchCommand("vault delete"));
        Assert.Contains("AUTH_REQUIRED", svc.DispatchCommand("vault reformat"));
        Assert.Contains("AUTH_REQUIRED", svc.DispatchCommand("update apply"));
        Assert.Contains("AUTH_REQUIRED", svc.DispatchCommand("quit"));

        // …an inline password satisfies fresh directly…
        Assert.StartsWith("err PHRASE_REQUIRED",   // passed auth — now wants the phrase
            svc.DispatchCommand("unenroll" + trailer));

        // …and ordinary verbs still pass on the open gate window.
        Assert.StartsWith("ok", svc.DispatchCommand("pause 5"));
    }

    [Fact]
    public async Task Token_session_passes_the_gate_but_not_fresh()
    {
        var handler = new ScriptHandler();
        handler.Enqueue(HttpStatusCode.OK, TokenJson());
        var auth = new AuthService(Cfg, handler);
        AuthService.SetCurrent(auth);

        AuthService.FreshTtl = TimeSpan.FromMilliseconds(60);
        Assert.True((await auth.SignIn("a@b.c", "pw-123456")).Ok);
        Assert.True(auth.Authorized);

        Thread.Sleep(120);
        // Live tokens keep ordinary gating open (the session is real),
        // but a stale fresh window can't drive a destructive op.
        Assert.True(auth.Authorize(null, out _));
        Assert.False(auth.Authorize(null, out string err, fresh: true));
        Assert.Contains("AUTH_REQUIRED", err);
        // Fresh is satisfiable: the password re-verifies inline.
        Assert.True(auth.Authorize("pw-123456", out _, fresh: true));
    }

    [Fact]
    public async Task LockSession_drops_authorization_without_signing_out()
    {
        var handler = new ScriptHandler();
        handler.Enqueue(HttpStatusCode.OK, TokenJson());
        var auth = new AuthService(Cfg, handler);
        AuthService.SetCurrent(auth);
        Assert.True((await auth.SignIn("a@b.c", "pw-123456")).Ok);

        int ended = 0;
        auth.SessionEnded += () => ended++;
        auth.LockSession();

        Assert.Equal(1, ended);
        Assert.False(auth.SessionLive);
        Assert.False(auth.Authorized);
        Assert.False(auth.Authorize(null, out _));
        // …but the install is still bound — sign-out never ran, so the
        // machine stays armed.
        Assert.True(auth.ArmedForAutoLock);
    }

    [Fact]
    public void Reformat_routes_through_dispatch_and_reaches_the_engine()
    {
        // The UI's Reformat button now drives the same dispatch verb IPC
        // does — an authorized call must reach TryReformat (which refuses
        // for want of a held secret), not fall to "unknown command".
        KeyConfig cfg = BoundConfig("acct-pw");
        var auth = new AuthService(Cfg, new ScriptHandler());
        AuthService.SetCurrent(auth);
        using var svc = new GuardService(cfg, devMode: false, forceClassic: false);

        string trailer = " |auth " + Convert.ToBase64String(
            Encoding.UTF8.GetBytes("acct-pw"));
        string reply = svc.DispatchCommand("vault reformat 64" + trailer);
        Assert.DoesNotContain("AUTH_REQUIRED", reply);
        Assert.DoesNotContain("unknown vault command", reply);
        Assert.StartsWith("err", reply); // the engine refused — no held secret
    }

    [Fact]
    public void Ungated_installs_are_untouched()
    {
        // No account → no gate at all: freshness can't soft-lock a
        // pre-account install.
        KeyConfig cfg = BoundConfig("acct-pw");
        cfg.Account = null;
        AuthService.SetCurrent(new AuthService(Cfg, new ScriptHandler()));
        using var svc = new GuardService(cfg, devMode: false, forceClassic: false);

        AuthService.FreshTtl = TimeSpan.FromMilliseconds(1);
        Thread.Sleep(30);
        Assert.StartsWith("ok", svc.DispatchCommand("pause 1"));
        Assert.StartsWith("ok", svc.DispatchCommand("resume"));
    }
}
