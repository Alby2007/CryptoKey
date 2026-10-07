using System.IO.Pipes;
using System.Text;
using Xunit;

namespace CryptoKey.Tests;

/// <summary>
/// M5 — the control pipe must not serve as a credential spigot:
/// lines are capped at 4 KiB server-side (a hostile client can't stream
/// an unbounded buffer), and the client verifies the server's process
/// image before writing (commands carry the account password and the
/// recovery phrase — a squatter must never see them).
/// </summary>
public sealed class IpcHardeningTests : IDisposable
{
    private sealed class InlineDispatcher : IUiDispatcher
    {
        public void Post(Action work) => work();
        public T Send<T>(Func<T> work) => work();
    }

    // Real guards on this box own the production name — test servers bind
    // an isolated one so connects can't land on the live endpoint.
    public IpcHardeningTests()
    {
        IpcServer.PipeName = "cryptokey-ctl-test-" + Guid.NewGuid().ToString("N");
    }

    public void Dispose()
    {
        IpcServer.PipeName = "cryptokey-ctl";
        TestPlatform.TestIpcSecurity.ServerIsOurs = true;
    }

    [Fact]
    public async Task Bounded_read_returns_short_lines()
    {
        using var ms = new MemoryStream(Encoding.UTF8.GetBytes("status\n"));
        using var reader = new StreamReader(ms);
        string? line = await IpcServer.ReadLineBounded(
            reader, IpcServer.MaxLineChars, CancellationToken.None);
        Assert.Equal("status", line);
    }

    [Fact]
    public async Task Bounded_read_drops_oversized_lines()
    {
        string hostile = new string('x', IpcServer.MaxLineChars + 64) + "\n";
        using var ms = new MemoryStream(Encoding.UTF8.GetBytes(hostile));
        using var reader = new StreamReader(ms);
        string? line = await IpcServer.ReadLineBounded(
            reader, IpcServer.MaxLineChars, CancellationToken.None);
        Assert.Null(line);
    }

    [Fact]
    public async Task Bounded_read_accepts_exactly_max()
    {
        string edge = new string('y', IpcServer.MaxLineChars) + "\n";
        using var ms = new MemoryStream(Encoding.UTF8.GetBytes(edge));
        using var reader = new StreamReader(ms);
        string? line = await IpcServer.ReadLineBounded(
            reader, IpcServer.MaxLineChars, CancellationToken.None);
        Assert.Equal(IpcServer.MaxLineChars, line!.Length);
    }

    [Fact]
    public void Server_dispatches_and_client_gets_reply()
    {
        int calls = 0;
        using var server = new IpcServer(new InlineDispatcher(),
            line => { calls++; return "ok echo:" + line; });
        server.Start();
        Assert.Equal("ok echo:status", IpcClient.Send("status", 2000));
        Assert.Equal(1, calls);
    }

    [Fact]
    public void Oversized_client_line_never_reaches_the_handler()
    {
        int calls = 0;
        using var server = new IpcServer(new InlineDispatcher(),
            line => { calls++; return "ok"; });
        server.Start();

        // A client that bypasses IpcClient's pre-check and streams a
        // hostile line directly: the server drops it without dispatch.
        using var pipe = new NamedPipeClientStream(
            ".", IpcServer.PipeName, PipeDirection.InOut, PipeOptions.None);
        pipe.Connect(2000);
        byte[] payload = Encoding.UTF8.GetBytes(
            new string('z', IpcServer.MaxLineChars + 128) + "\n");
        pipe.Write(payload, 0, payload.Length);
        pipe.Flush();
        // Give the accept loop a beat to read + drop the connection.
        Thread.Sleep(400);
        Assert.Equal(0, calls);
    }

    [Fact]
    public void Client_refuses_a_pipe_server_that_isnt_ours()
    {
        int calls = 0;
        using var server = new IpcServer(new InlineDispatcher(),
            line => { calls++; return "ok"; });
        server.Start();
        TestPlatform.TestIpcSecurity.ServerIsOurs = false;

        // The squatter impersonates the endpoint — the client must drop
        // the connection before writing the command (which could carry
        // a password or the recovery phrase).
        Assert.Null(IpcClient.Send("unenroll |auth secret", 2000));
        Assert.Equal(0, calls);
    }
}
