using System.IO.Pipes;
using System.Text;

namespace CryptoKey;

/// <summary>
/// Control channel for the running guard — one text line in, one line out
/// ("ok ..." / "err ..."). Named pipe on Windows (DACL'd to the user);
/// .NET maps the same API onto an $TMPDIR unix socket on macOS. Commands
/// are marshaled onto the UI thread before dispatch.
/// </summary>
internal sealed class IpcServer : IDisposable
{
    /// <summary>The well-known control endpoint. Mutable only so tests can
    /// bind an isolated name — production never changes it.</summary>
    public static string PipeName { get; internal set; } = "cryptokey-ctl";

    // A connected client that never writes must not starve everyone behind
    // it — connections are handled sequentially.
    private static readonly TimeSpan ReadTimeout = TimeSpan.FromSeconds(5);

    /// <summary>Longest command a client may send — commands are short
    /// (status / unenroll &lt;b64&gt; / |auth trailers); anything longer is
    /// a hostile stream, dropped rather than buffered.</summary>
    internal const int MaxLineChars = 4096;

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
        // The first served instance doubles as the name anchor: created
        // with FirstPipeInstance so a pre-bound name (a squatter that beat
        // us) is detected. It stays in the accept rotation — a held but
        // never-served instance would silently eat client connects.
        bool first = true;
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                using NamedPipeServerStream pipe = first
                    ? CreateAnchor()
                    : CreatePipe(out _);
                first = false;
                await pipe.WaitForConnectionAsync(_cts.Token);

                using var reader = new StreamReader(pipe);
                var writer = new StreamWriter(pipe) { AutoFlush = true };
                string? line;
                using (var readTimeout = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token))
                {
                    readTimeout.CancelAfter(ReadTimeout);
                    try
                    {
                        line = await ReadLineBounded(reader, MaxLineChars, readTimeout.Token);
                    }
                    catch (OperationCanceledException) when (!_cts.IsCancellationRequested)
                    {
                        continue; // client went silent — drop it, keep accepting
                    }
                }
                if (line == null)
                    continue; // oversized or aborted line — drop the client
                string response = Dispatch(line);
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

    /// <summary>First-instance create with squat detection — falls back to
    /// a normal instance when the name is contested (clients verify the
    /// server image, so serving on a contested name is still safe).</summary>
    private NamedPipeServerStream CreateAnchor()
    {
        try
        {
            return Platform.Services.Ipc.CreateAnchorPipe();
        }
        catch (Exception ex)
        {
            Console.WriteLine(
                $"[ipc] pipe name already bound — possible squat ({ex.Message}); clients verify the peer.");
            return CreatePipe(out _);
        }
    }

    /// <summary>
    /// Bounded line read: at most <paramref name="maxChars"/> characters up
    /// to the first '\n'. Returns null on overflow or EOF before a full
    /// line — ReadLineAsync would buffer a hostile unbounded stream.
    /// </summary>
    internal static async Task<string?> ReadLineBounded(
        StreamReader reader, int maxChars, CancellationToken ct)
    {
        var sb = new StringBuilder(Math.Min(maxChars, 256));
        var buf = new char[256];
        while (true)
        {
            int n = await reader.ReadAsync(buf.AsMemory(0, buf.Length), ct);
            if (n == 0)
                return null;
            for (int i = 0; i < n; i++)
            {
                if (buf[i] == '\n')
                {
                    // Discard anything buffered past the newline — the
                    // protocol is one request, one response.
                    return sb.ToString().TrimEnd('\r');
                }
                sb.Append(buf[i]);
                if (sb.Length > maxChars)
                    return null;
            }
        }
    }

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
