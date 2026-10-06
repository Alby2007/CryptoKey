using CryptoKey.Ui;

namespace CryptoKey;

/// <summary>
/// The guard engine's own thread: an STA WinForms pump hosting exactly what
/// the main thread used to — <see cref="GuardService"/> (and through it the
/// <see cref="UsbMonitor"/> window, the classic lock overlay and its low-level
/// hooks, the secure-surface spawn) plus the IPC server. The Avalonia UI runs
/// on the main thread, so a dashboard render stall or crash can never starve
/// the lock's hooks.
///
/// Lifetime: <c>Application.Exit()</c> (quit, panic, takeover) ends this
/// pump; the engine disposes itself, then raises <see cref="Stopped"/> so
/// the UI shuts down after it — never the other way round.
/// </summary>
internal sealed class EngineHost
{
    private Thread? _thread;
    private GuardService? _service;
    private IpcServer? _ipc;

    public GuardClient Client { get; private set; } = null!;

    /// <summary>Non-null when the engine failed to start.</summary>
    public string? Error { get; private set; }

    /// <summary>Raised on the engine thread after it has fully torn down.</summary>
    public event Action? Stopped;

    public bool Running => _thread?.IsAlive == true;

    /// <param name="intercept">IPC pre-dispatch: return a reply to handle a
    /// line host-side (e.g. `open`), or null to pass it to the guard.</param>
    public static EngineHost Start(KeyConfig config, bool devMode, bool forceClassic,
        Func<string, string?> intercept)
    {
        var host = new EngineHost();
        using var ready = new ManualResetEventSlim();
        host._thread = new Thread(() => host.Main(config, devMode, forceClassic, intercept, ready))
        {
            Name = "ck-engine",
            IsBackground = false,
        };
        host._thread.SetApartmentState(ApartmentState.STA);
        host._thread.Start();
        if (!ready.Wait(TimeSpan.FromSeconds(15)) || !host.Running)
            host.Error ??= "engine thread did not start";
        return host;
    }

    private void Main(KeyConfig config, bool devMode, bool forceClassic,
        Func<string, string?> intercept, ManualResetEventSlim ready)
    {
        try
        {
            _service = new GuardService(config, devMode, forceClassic);
            GuardService svc = _service;
            Client = new GuardClient(svc, config, devMode, UiRuntime.Post);
            _ipc = new IpcServer(svc.UiDispatcher, line => intercept(line) ?? svc.DispatchCommand(line));
            // An engine-thread exception while locked can leave input
            // swallowed behind a dead overlay — an invisible soft-brick.
            // Fail dead instead: free the input, then kill the process.
            Application.ThreadException += (_, e) =>
            {
                Console.WriteLine($"[guard] Fatal engine error: {e.Exception}");
                try { svc.Log($"Fatal engine error: {e.Exception.GetType().Name}: {e.Exception.Message}"); }
                catch (Exception) { }
                try { svc.ReleaseInput(); }
                catch (Exception) { }
                Environment.Exit(2);
            };
            svc.Start();
            _ipc.Start(svc.Log);
        }
        catch (Exception ex)
        {
            Error = ex.Message;
            try { _ipc?.Dispose(); } catch (Exception) { }
            try { _service?.Dispose(); } catch (Exception) { }
            ready.Set();
            return;
        }

        ready.Set();
        try
        {
            Application.Run();
        }
        finally
        {
            try { Client.Dispose(); } catch (Exception) { }
            try { _ipc.Dispose(); } catch (Exception) { }
            try { _service.Dispose(); } catch (Exception) { }
            try { Stopped?.Invoke(); } catch (Exception) { }
        }
    }

    /// <summary>Stop the engine pump (UI-initiated shutdown) and wait for teardown.</summary>
    public void StopAndJoin(int timeoutMs = 8000)
    {
        if (_thread == null || !_thread.IsAlive)
            return;
        try { _service?.UiDispatcher.Post(Application.ExitThread); }
        catch (Exception) { }
        _thread.Join(timeoutMs);
    }
}
