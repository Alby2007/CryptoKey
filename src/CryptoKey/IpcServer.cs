using System.IO.Pipes;
using System.Security.Principal;

namespace CryptoKey;

/// <summary>
/// Named-pipe control channel for the running guard. One text line in, one
/// line out ("ok ..." / "err ..."). Commands are marshaled onto the UI thread
/// before dispatch. Default ACL = current user only.
/// </summary>
internal sealed class IpcServer : IDisposable
{
    public const string PipeName = "cryptokey-ctl";

    // A connected client that never writes must not starve everyone behind
    // it — connections are handled sequentially.
    private static readonly TimeSpan ReadTimeout = TimeSpan.FromSeconds(5);

    private readonly Control _marshal;
    private readonly Func<string, string> _handler;
    private readonly CancellationTokenSource _cts = new();
    private Task? _loop;

    public IpcServer(Control marshal, Func<string, string> handler)
    {
        _marshal = marshal;
        _handler = handler;
    }

    public void Start() => _loop = AcceptLoop();

    private async Task AcceptLoop()
    {
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                using var pipe = CreatePipe();
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

    // Two layers: the SACL's Medium integrity label lets the normal
    // (medium-IL) CLI reach an *elevated* guard — MIC no-write-up would
    // otherwise block it — while the DACL scopes access to the owning user.
    // The pipe lives in the global namespace, so a World DACL would let any
    // other session on the machine send pause/lock/quit.
    private static NamedPipeServerStream CreatePipe()
    {
        string sid = WindowsIdentity.GetCurrent().User?.Value ?? "WD";

        // Applying a SACL needs SE_SECURITY_PRIVILEGE — non-elevated guards
        // can't set the integrity label, and don't need it: a medium-IL pipe
        // is reachable by medium clients by default. Elevated guards must
        // have it or the normal CLI can't write, so try SACL first and fall
        // back to DACL-only.
        try
        {
            var security = new PipeSecurity();
            security.SetSecurityDescriptorSddlForm($"D:(A;;GA;;;{sid})S:(ML;;NW;;;ME)");
            return Create(security);
        }
        catch (Exception)
        {
            var security = new PipeSecurity();
            security.SetSecurityDescriptorSddlForm($"D:(A;;GA;;;{sid})");
            return Create(security);
        }

        static NamedPipeServerStream Create(PipeSecurity security)
            => NamedPipeServerStreamAcl.Create(
                PipeName, PipeDirection.InOut,
                NamedPipeServerStream.MaxAllowedServerInstances,
                PipeTransmissionMode.Byte, PipeOptions.Asynchronous,
                0, 0, security, HandleInheritability.None);
    }

    private string Dispatch(string line)
    {
        try
        {
            return (string?)_marshal.Invoke(_handler, line) ?? "err no response";
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
