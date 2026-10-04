using System.IO.Pipes;

namespace CryptoKey;

/// <summary>CLI side of the guard control pipe: send one line, read one line.</summary>
internal static class IpcClient
{
    /// <summary>Server reply line, or null when no guard is listening.</summary>
    public static string? Send(string command, int timeoutMs = 1500)
    {
        try
        {
            using var pipe = new NamedPipeClientStream(
                ".", IpcServer.PipeName, PipeDirection.InOut, PipeOptions.None);
            pipe.Connect(timeoutMs);
            using var reader = new StreamReader(pipe);
            using var writer = new StreamWriter(pipe) { AutoFlush = true };
            writer.WriteLine(command);
            return reader.ReadLine();
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
