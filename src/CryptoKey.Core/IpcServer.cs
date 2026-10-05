using System.IO.Pipes;

namespace CryptoKey;

/// <summary>
/// Control channel for the running guard — one text line in, one line out
/// ("ok ..." / "err ..."). Named pipe on Windows (DACL'd to the user);
/// .NET maps the same API onto an $TMPDIR unix socket on macOS. Commands
/// are marshaled onto the UI thread before dispatch.
/// </summary>
internal sealed class IpcServer : IDisposable
{
    public const string PipeName = "cryptokey-ctl";

    // A connected client that never writes must not starve everyone behind
    // it — connections are handled sequentially.
    private static readonly TimeSpan ReadTimeout = TimeSpan.FromSeconds(5);

    private readonly IUiDispatcher _marshal;
    private readonly Func<string, string> _handler;
    private readonly CancellationTokenSource _cts = new();
    private Task? _loop;

    public IpcServer(IUiDispatcher marshal, Func<string, string> handler)
    {
        _marshal = marshal;
        _handler = handler;
    }

    /// <summary>Whether the pipe carries the medium-integrity label (false = DACL-only).</summary>
    public bool IntegrityLabeled { get; private set; }

    public void Start(Action<string>? log = null)
    {
        // Probe the security model once so the fallback is in the log — an
        // elevated guard that silently ends up DACL-only would strand the CLI.
        try
        {
            using var probe = CreatePipe(out bool labeled);
            IntegrityLabeled = labeled;
            if (log != null)
            {
                log(labeled
                    ? "IPC pipe up (integrity label applied — CLI works elevated)."
                    : Platform.Services.Ipc.Elevated
                        ? "IPC pipe up WITHOUT integrity label — elevated guard may be unreachable from the CLI."
                        : "IPC pipe up (per-user ACL — normal at medium integrity).");
            }
        }
        catch (Exception ex)
        {
            log?.Invoke($"IPC security probe failed: {ex.Message}");
        }
        _loop = AcceptLoop();
    }

    private async Task AcceptLoop()
    {
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                using var pipe = CreatePipe(out _);
                await pipe.WaitForConnectionAsync(_cts.Token);

                using var reader = new StreamReader(pipe);
                var writer = new StreamWriter(pipe) { AutoFlush = true };
                string? line;
                using (var readTimeout = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token))
                {
                    readTimeout.CancelAfter(ReadTimeout);
                    try
                    {
                        line = await reader.ReadLineAsync(readTimeout.Token);
                    }
                    catch (OperationCanceledException) when (!_cts.IsCancellationRequested)
                    {
                        continue; // client went silent — drop it, keep accepting
                    }
                }
                string response = Dispatch(line ?? "");
                await writer.WriteLineAsync(response.AsMemory(), _cts.Token);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ipc] {ex.Message}");
                try { await Task.Delay(250, _cts.Token); }
                catch (OperationCanceledException) { break; }
            }
        }
    }

    // Pipe hardening is per-platform: Windows wraps it in a user DACL plus
    // a Medium-integrity SACL label (so the normal CLI reaches an elevated
    // guard); macOS's unix-domain socket lives under $TMPDIR already.
    private static NamedPipeServerStream CreatePipe(out bool integrityLabeled)
        => Platform.Services.Ipc.CreatePipe(out integrityLabeled);

    private string Dispatch(string line)
    {
        try
        {
            return _marshal.Send(() => _handler(line));
        }
        catch (Exception)
        {
            return "err guard unavailable";
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        try { _loop?.Wait(500); }
        catch { }
        _cts.Dispose();
    }
}
