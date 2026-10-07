using System.Net;
using System.Text;
using System.Text.Json;
using Xunit;

namespace CryptoKey.Tests;

/// <summary>
/// Phase 4 hardening — L1 phrase single-flight + snapshot, L2 StrictTamper
/// default, L3 supabase trust-root pin, L4 https-only alerts, L5 dev-flag
/// parse surface, L6 persisted throttles.
/// </summary>
public class HardeningTests : IDisposable
{
    private static readonly SupabaseConfig Cfg = new()
    {
        ProjectUrl = "https://test.supabase.co",
        AnonKey = "test-anon-key-0123456789abcdef",
    };

    public HardeningTests()
    {
        AuthService.SetCurrent(null);
        TokenStore.Clear();
        AuthService.PendingStore.Clear();
        ThrottleStore.Clear();
        TestPlatform.TestUsbEnumerator.Disks.Clear();
    }

    public void Dispose()
    {
        AuthService.SetCurrent(null);
        TokenStore.Clear();
        AuthService.PendingStore.Clear();
        ThrottleStore.Clear();
        TestPlatform.TestUsbEnumerator.Disks.Clear();
    }

    private sealed class ScriptHandler : HttpMessageHandler
    {
        private readonly Queue<(HttpStatusCode Code, string Body)> _responses = new();
        public List<string> Requests { get; } = new();
        public void Enqueue(HttpStatusCode code, string body) => _responses.Enqueue((code, body));
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string body = request.Content?.ReadAsStringAsync().Result ?? "";
            Requests.Add($"{request.Method} {request.RequestUri} {body}");
            var r = _responses.Count > 0 ? _responses.Dequeue()
                : (HttpStatusCode.InternalServerError, "{}");
            return Task.FromResult(new HttpResponseMessage(r.Item1)
            {
                Content = new StringContent(r.Item2, Encoding.UTF8, "application/json"),
            });
        }
    }

    private static KeyConfig FreshCfg(string dir, byte[] secret)
    {
        KeyConfig cfg = TestDisk.NewConfig(secret);
        cfg.Guard.Watchdog = false;
        cfg.Guard.UpdateCheckEnabled = false;
        TestDisk.WriteKeyfile(dir, secret, cfg);
        AuthService.SetCurrent(new AuthService(null, null));
        return cfg;
    }

    // ------------------------------------------------------------ L1

    [Fact]
    public void Second_phrase_submit_drops_while_first_verifies()
    {
        string dir = TestDisk.TempDir();
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig cfg = FreshCfg(dir, secret);
        using var svc = new GuardService(cfg, devMode: false, forceClassic: false);
        svc.Start();
        Assert.StartsWith("ok", svc.DispatchCommand("lock"));
        var surface = TestPlatform.TestLockSurfaceFactory.Last!;

        // Two Enters back-to-back: the first claims the slot for its whole
        // PBKDF2; the second is wiped + ignored — parallelism can't multiply
        // brute-force throughput past the backoff ladder.
        surface.Submit("AAAAA-BBBBB-CCCCC-DDDDD");
        surface.Submit("BBBBB-CCCCC-DDDDD-EEEEE");
        Assert.True(SpinWait.SpinUntil(
            () => surface.FailedAttempts > 0, TimeSpan.FromSeconds(15)),
            "first attempt never landed");
        // Give the second a chance to land if the gate leaked.
        Thread.Sleep(400);
        Assert.Equal(1, surface.FailedAttempts);
    }

    [Fact]
    public void Phrase_slot_releases_after_the_result_lands()
    {
        string dir = TestDisk.TempDir();
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig cfg = FreshCfg(dir, secret);
        using var svc = new GuardService(cfg, devMode: false, forceClassic: false);
        svc.Start();
        Assert.StartsWith("ok", svc.DispatchCommand("lock"));
        var surface = TestPlatform.TestLockSurfaceFactory.Last!;

        surface.Submit("AAAAA-BBBBB-CCCCC-DDDDD");
        Assert.True(SpinWait.SpinUntil(
            () => surface.FailedAttempts > 0, TimeSpan.FromSeconds(15)));
        // The slot freed with the result — a later attempt isn't wedged.
        surface.Submit("BBBBB-CCCCC-DDDDD-EEEEE");
        Assert.True(SpinWait.SpinUntil(
            () => surface.FailedAttempts > 1, TimeSpan.FromSeconds(15)),
            "slot stayed busy after the result landed");
    }

    [Fact]
    public void Orphaned_verify_result_cannot_count_against_a_new_session()
    {
        string dir = TestDisk.TempDir();
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig cfg = FreshCfg(dir, secret);
        using var svc = new GuardService(cfg, devMode: false, forceClassic: false);
        svc.Start();
        var mon = TestPlatform.TestKeyMonitorFactory.Last!;
        var disk = TestDisk.For(dir);
        Assert.StartsWith("ok", svc.DispatchCommand("lock"));
        var surface = TestPlatform.TestLockSurfaceFactory.Last!;

        // Submit, then unlock by key while PBKDF2 is still running — the
        // ticket bumps, so the stale result lands nowhere.
        surface.Submit("AAAAA-BBBBB-CCCCC-DDDDD");
        mon.FireChecked(disk);
        Assert.True(SpinWait.SpinUntil(
            () => svc.State == GuardState.Unlocked, TimeSpan.FromSeconds(15)),
            "key unlock never landed");

        // Relock: the orphaned result must not have counted mid-flight, and
        // the busy slot must be free for the new session's first attempt.
        // (Re-grab the surface — the test shim's IsOverlay polarity makes
        // EnsureSurfaceMode swap instances on every lock.)
        Assert.StartsWith("ok", svc.DispatchCommand("lock"));
        surface = TestPlatform.TestLockSurfaceFactory.Last!;
        surface.Submit("BBBBB-CCCCC-DDDDD-EEEEE");
        Assert.True(SpinWait.SpinUntil(
            () => surface.FailedAttempts > 0, TimeSpan.FromSeconds(15)),
            $"busy slot stayed wedged — state={svc.State} " +
            $"svcFails={svc.FailedAttempts} surfFails={surface.FailedAttempts} " +
            $"status={surface.LastStatus ?? "null"} cd={surface.CooldownUntil} " +
            $"ticket={svc.PhraseTicket} busy={svc.PhraseBusy}");
        Assert.Equal(1, surface.FailedAttempts);
    }

    [Fact]
    public void Config_change_mid_verify_holds_the_door_closed()
    {
        string dir = TestDisk.TempDir();
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig cfg = FreshCfg(dir, secret);
        using var svc = new GuardService(cfg, devMode: false, forceClassic: false);
        svc.Start();
        Assert.StartsWith("ok", svc.DispatchCommand("lock"));
        var surface = TestPlatform.TestLockSurfaceFactory.Last!;

        // The CORRECT phrase, but the verifier is swapped while PBKDF2 runs:
        // a match against the retired hash must never unlock. (Direct field
        // mutation — ChangePassphrase would PBKDF2 first and lose the race.)
        surface.Submit("passphrase-ok");
        cfg.PassphraseHash = Convert.ToBase64String(new byte[32]);
        Assert.True(SpinWait.SpinUntil(
            () => surface.LastStatus?.Contains("try again") == true
                  || svc.State == GuardState.Unlocked,
                TimeSpan.FromSeconds(15)),
            surface.LastStatus ?? "no status");
        Assert.Equal(GuardState.Locked, svc.State);
        Assert.Equal(0, surface.FailedAttempts); // not counted as a failure either
    }

    // ------------------------------------------------------------ L2

    [Fact]
    public void New_enrollment_defaults_strict_tamper_on()
        => Assert.True(TestDisk.NewConfig(TestDisk.RandomSecret()).Guard.StrictTamper);

    [Fact]
    public void Loaded_legacy_config_keeps_its_stored_strict_tamper()
    {
        // A pre-L2 config.json has no strictTamper field — it deserializes to
        // false and stays false; the new default only bites via CreateNew.
        var loaded = JsonSerializer.Deserialize<KeyConfig>("""{"deviceSerial":"S"}""");
        Assert.NotNull(loaded);
        Assert.False(loaded!.Guard.StrictTamper);
    }

    // ------------------------------------------------------------ L3

    [Fact]
    public async Task Trust_root_mismatch_refuses_online_flows()
    {
        var handler = new ScriptHandler();
        var auth = new AuthService(Cfg, handler);
        KeyConfig cfg = TestDisk.NewConfig(TestDisk.RandomSecret());
        cfg.Account = AccountRecord.Create("u1", "a@b.c", "acct-pw",
            projectUrl: "https://evil.supabase.co"); // bound elsewhere
        auth.BindConfig(cfg);

        Assert.True(auth.TrustRootMismatch);
        AuthResult r = await auth.SignIn("a@b.c", "acct-pw");
        Assert.False(r.Ok);
        Assert.Contains("different project", r.Error);
        Assert.Empty(handler.Requests); // nothing reached the wire
    }

    [Fact]
    public void Matching_pin_reads_clean()
    {
        var auth = new AuthService(Cfg, new ScriptHandler());
        KeyConfig cfg = TestDisk.NewConfig(TestDisk.RandomSecret());
        cfg.Account = AccountRecord.Create("u1", "a@b.c", "acct-pw",
            projectUrl: "https://test.supabase.co/"); // trailing slash normalizes
        auth.BindConfig(cfg);
        Assert.False(auth.TrustRootMismatch);
    }

    [Fact]
    public void Unpinned_legacy_record_reads_clean()
    {
        // Records written before the pin have no basis to compare — the file
        // itself is the root until the next sign-in stamps it.
        var auth = new AuthService(Cfg, new ScriptHandler());
        KeyConfig cfg = TestDisk.NewConfig(TestDisk.RandomSecret());
        cfg.Account = AccountRecord.Create("u1", "a@b.c", "acct-pw");
        auth.BindConfig(cfg);
        Assert.False(auth.TrustRootMismatch);
    }

    [Fact]
    public void Editing_the_pinned_project_trips_keyfile_attestation()
    {
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig cfg = TestDisk.NewConfig(secret);
        cfg.Account = AccountRecord.Create("u1", "a@b.c", "acct-pw",
            projectUrl: "https://test.supabase.co");
        byte[] file = KeyVerifier.WrapKeyfile(secret, cfg);

        // Off-app edit to match a swapped supabase.json — the canon covers
        // the pin, so it mismatches like any covered field.
        cfg.Account.ProjectUrl = "https://evil.supabase.co";
        Assert.True(KeyVerifier.TryUnwrapKeyfile(file, cfg,
            out _, out AttestState attest, out _));
        Assert.Equal(AttestState.Mismatch, attest);
    }

    [Fact]
    public void Candidate_path_honors_env_override_only_in_debug()
    {
        string custom = Path.Combine(TestInit.Dir, "somewhere-else.json");
        string? had = Environment.GetEnvironmentVariable("CRYPTOKEY_SUPABASE_JSON");
        Environment.SetEnvironmentVariable("CRYPTOKEY_SUPABASE_JSON", custom);
        try
        {
#if DEBUG
            Assert.Equal(custom, SupabaseConfig.CandidatePath());
#else
            Assert.NotEqual(custom, SupabaseConfig.CandidatePath());
#endif
        }
        finally
        {
            Environment.SetEnvironmentVariable("CRYPTOKEY_SUPABASE_JSON", had);
        }
    }

    // ------------------------------------------------------------ L4

    [Theory]
    [InlineData("https://ntfy.sh/ck-alerts", true)]
    [InlineData("https://hooks.example.com/x?y=1", true)]
    [InlineData("http://ntfy.sh/ck-alerts", false)]
    [InlineData("ftp://x", false)]
    [InlineData("ntfy.sh/topic", false)]
    [InlineData("javascript:alert(1)", false)]
    [InlineData("not a url", false)]
    public void Alert_url_requires_absolute_https(string url, bool allowed)
        => Assert.Equal(allowed, AlertService.IsAllowedUrl(url));

    [Fact]
    public void Http_alert_url_is_dropped_with_a_logged_reason()
    {
        int logged = 0;
        AlertService.Send("http://ntfy.sh/topic", "t", "b", _ => logged++);
        Assert.Equal(1, logged);
    }

    // ------------------------------------------------------------ L5

    [Fact]
    public void Dev_flag_parses_only_where_the_combo_exists()
    {
        // The shipped Release binary must never arm the panic combo from a
        // launch argument — every parse site funnels through ParseDev.
#if DEBUG
        Assert.True(DevFlags.Available);
        Assert.True(DevFlags.ParseDev(new[] { "guard", "--dev" }));
#else
        Assert.False(DevFlags.Available);
        Assert.False(DevFlags.ParseDev(new[] { "guard", "--dev" }));
#endif
        Assert.False(DevFlags.ParseDev(new[] { "--classic" }));
    }

    // ------------------------------------------------------------ L6

    [Fact]
    public void Auth_lockout_survives_a_restart()
    {
        var auth = new AuthService(Cfg, new ScriptHandler());
        KeyConfig cfg = TestDisk.NewConfig(TestDisk.RandomSecret());
        cfg.Account = AccountRecord.Create("u1", "a@b.c", "acct-pw");
        auth.BindConfig(cfg);

        for (int i = 0; i < 5; i++)
            Assert.False(auth.Authorize("wrong-pw", out _));
        Assert.True(auth.CooldownRemaining > 0);

        // "Restart": drop the in-memory cache; the sealed file still stands.
        ThrottleStore.ResetCache();
        var auth2 = new AuthService(Cfg, new ScriptHandler());
        auth2.BindConfig(cfg);
        Assert.True(auth2.CooldownRemaining > 0);
        Assert.False(auth2.Authorize("acct-pw", out string err));
        Assert.Contains("Too many attempts", err);
    }

    [Fact]
    public void Auth_success_clears_the_persisted_ladder()
    {
        var auth = new AuthService(Cfg, new ScriptHandler());
        KeyConfig cfg = TestDisk.NewConfig(TestDisk.RandomSecret());
        cfg.Account = AccountRecord.Create("u1", "a@b.c", "acct-pw");
        auth.BindConfig(cfg);

        for (int i = 0; i < 3; i++)
            Assert.False(auth.Authorize("wrong-pw", out _));
        Assert.Equal(3, ThrottleStore.Shared.AuthFailures);

        ThrottleStore.ResetCache();
        var auth2 = new AuthService(Cfg, new ScriptHandler());
        auth2.BindConfig(cfg);
        Assert.Equal(3, ThrottleStore.Shared.AuthFailures); // streak survives

        Assert.True(auth2.Authorize("acct-pw", out _));
        Assert.Equal(0, ThrottleStore.Shared.AuthFailures);
        Assert.Equal(30, ThrottleStore.Shared.AuthCooldownSeconds);
    }

    [Fact]
    public void Corrupt_throttle_file_loads_fresh()
    {
        File.WriteAllBytes(ThrottleStore.StorePath,
            Encoding.UTF8.GetBytes("not a sealed blob"));
        ThrottleStore.ResetCache();
        ThrottleState s = ThrottleStore.Shared;
        Assert.Equal(0, s.AuthFailures);
        Assert.Equal(0, s.PhraseFailures);
    }

    [Fact]
    public void Phrase_ladder_adopts_persisted_freeze_on_lock()
    {
        string dir = TestDisk.TempDir();
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig cfg = FreshCfg(dir, secret);

        // Session 1: three bad phrases → the 15s freeze persists to disk.
        using (var svc1 = new GuardService(cfg, devMode: false, forceClassic: false))
        {
            svc1.Start();
            Assert.StartsWith("ok", svc1.DispatchCommand("lock"));
            var surface1 = TestPlatform.TestLockSurfaceFactory.Last!;
            for (int i = 0; i < 3; i++)
            {
                surface1.Submit("AAAAA-BBBBB-CCCCC-DDDDD");
                Assert.True(SpinWait.SpinUntil(
                    () => surface1.FailedAttempts > i, TimeSpan.FromSeconds(15)),
                    $"failed attempt #{i + 1} never landed");
            }
            Assert.NotNull(surface1.CooldownUntil);
            Assert.True(SpinWait.SpinUntil(
                () => File.Exists(ThrottleStore.StorePath), TimeSpan.FromSeconds(5)),
                "throttle file never persisted");
        }

        // "Restart" — the new service adopts the persisted freeze instead of
        // handing the brute-forcer a fresh ladder.
        ThrottleStore.ResetCache();
        using (var svc2 = new GuardService(cfg, devMode: false, forceClassic: false))
        {
            svc2.Start();
            Assert.StartsWith("ok", svc2.DispatchCommand("lock"));
            var surface2 = TestPlatform.TestLockSurfaceFactory.Last!;
            Assert.True(SpinWait.SpinUntil(
                () => surface2.FailedAttempts >= 3, TimeSpan.FromSeconds(10)),
                "persisted failure streak wasn't adopted");
            Assert.NotNull(surface2.CooldownUntil); // the freeze bound again
        }
    }
}
