using System.IO.Pipes;

namespace CryptoKey;

/// <summary>
/// Named-pipe control channel for the running guard. One text line in, one
/// line out ("ok ..." / "err ..."). Commands are marshaled onto the UI thread
/// before dispatch. Default ACL = current user only.
/// </summary>
internal sealed class IpcServer : IDisposable
{
    public const string PipeName = "cryptokey-ctl";

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
                using var pipe = new NamedPipeServerStream(
                    PipeName, PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous);

                await pipe.WaitForConnectionAsync(_cts.Token);

                using var reader = new StreamReader(pipe);
                var writer = new StreamWriter(pipe) { AutoFlush = true };
                string? line = await reader.ReadLineAsync(_cts.Token);
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
