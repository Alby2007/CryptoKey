using CryptoKey.Ui;

namespace CryptoKey;

/// <summary>
/// One engine composition for both host shapes — <see cref="GuardService"/>
/// + optional <see cref="GuardClient"/> + <see cref="IpcServer"/> + the
/// fail-dead fatal-error policy, created on whatever thread's pump will run
/// it. <see cref="EngineHost"/> hosts it on a dedicated STA thread behind
/// the Avalonia UI; headless mode hosts it on the main thread — and now
/// gets the same ThreadException release-input policy (a crash while locked
/// there used to be an invisible soft-brick).
/// </summary>
internal sealed class EngineBundle : IDisposable
{
    private EngineBundle() { }

    public GuardService? Service { get; private set; }
    public GuardClient? Client { get; private set; }
    public IpcServer? Ipc { get; private set; }

    /// <summary>Non-null when engine bring-up failed (the bundle is already disposed).</summary>
    public string? Error { get; private set; }

    /// <param name="intercept">IPC pre-dispatch — a non-null reply handles the
    /// line host-side (e.g. `open`); null falls through to the guard.</param>
    /// <param name="withClient">also create the <see cref="GuardClient"/> UI facade.</param>
    /// <param name="postToUi">required when <paramref name="withClient"/> — the
    /// UI-thread poster GuardClient marshals engine events through.</param>
    public static EngineBundle Create(KeyConfig config, bool devMode, bool forceClassic,
        Func<string, string?>? intercept = null, bool withClient = false,
        Action<Action>? postToUi = null)
    {
        var b = new EngineBundle();
        try
        {
            b.Service = new GuardService(config, devMode, forceClassic);
            GuardService svc = b.Service;
            if (withClient)
            {
                b.Client = new GuardClient(svc, config, devMode,
                    postToUi ?? throw new ArgumentNullException(nameof(postToUi)));
            }
            b.Ipc = new IpcServer(svc.UiDispatcher, intercept != null
                ? line => intercept(line) ?? svc.DispatchCommand(line)
                : svc.DispatchCommand);
            InstallFatalPolicy(svc);
            svc.Start();
            b.Ipc.Start(svc.Log);
        }
        catch (Exception ex)
        {
            b.Error = ex.Message;
            try { b.Dispose(); } catch (Exception) { }
        }
        return b;
    }

    /// <summary>
    /// An engine-thread exception while locked can leave input swallowed
    /// behind a dead overlay — an invisible soft-brick. Fail dead instead:
    /// free the input, then kill the process (hooks die with it anyway).
    /// </summary>
    public static void InstallFatalPolicy(GuardService svc)
    {
        Application.ThreadException += (_, e) =>
        {
            Console.WriteLine($"[guard] Fatal engine error: {e.Exception}");
            try { svc.Log($"Fatal engine error: {e.Exception.GetType().Name}: {e.Exception.Message}"); }
            catch (Exception) { }
            try { svc.ReleaseInput(); }
            catch (Exception) { }
            Environment.Exit(2);
        };
    }

    /// <summary>Client → pipe → service: reverse construction order.</summary>
    public void Dispose()
    {
        try { Client?.Dispose(); } catch (Exception) { }
        try { Ipc?.Dispose(); } catch (Exception) { }
        try { Service?.Dispose(); } catch (Exception) { }
    }
}
