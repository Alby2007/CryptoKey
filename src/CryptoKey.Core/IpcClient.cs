using System.IO.Pipes;

namespace CryptoKey;

/// <summary>CLI side of the guard control pipe: send one line, read one line.</summary>
internal static class IpcClient
{
    /// <summary>Server reply line, or null when no guard is listening —
    /// including a connected pipe whose server isn't a CryptoKey image
    /// (a same-user squatter must never see command payloads: they carry
    /// the account password and the recovery phrase).</summary>
    public static string? Send(string command, int timeoutMs = 1500)
    {
        if (command.Length > IpcServer.MaxLineChars)
            return null; // never hand a hostile-sized payload to the wire
        try
        {
            // Asynchronous: without overlapped I/O a read can't be aborted
            // mid-flight, and the reply timeout below would hang forever
            // against a dead or hostile instance.
            using var pipe = new NamedPipeClientStream(
                ".", IpcServer.PipeName, PipeDirection.InOut,
                PipeOptions.Asynchronous);
            pipe.Connect(timeoutMs);
            if (!Platform.Services.Ipc.VerifyServerIsOurs(pipe))
                return null;
            using var reader = new StreamReader(pipe);
            using var writer = new StreamWriter(pipe) { AutoFlush = true };
            writer.WriteLine(command);
            // ReadLine has no built-in timeout — a guard wedged mid-dispatch
            // would hang the CLI forever. Same budget as the connect; the
            // reply is capped too.
            using var cts = new CancellationTokenSource(timeoutMs);
            try
            {
                return IpcServer.ReadLineBounded(
                    reader, IpcServer.MaxLineChars, cts.Token)
                    .GetAwaiter().GetResult();
            }
            catch (OperationCanceledException)
            {
                return null;
            }
        }
        catch (TimeoutException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
    }
}
