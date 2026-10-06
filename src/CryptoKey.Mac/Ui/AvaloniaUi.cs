using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Threading;

namespace CryptoKey;

/// <summary>
/// The Avalonia-backed pump — same contract as <see cref="MacPump"/> but the
/// UI thread is the real macOS main loop, so windows can actually render.
/// IpcServer's <c>Send</c> marshals in through Dispatcher.UIThread exactly
/// like the BlockingCollection version.
/// </summary>
internal sealed class AvaloniaUiDispatcher : IUiDispatcher, IAppLifetime
{
    public void Post(Action work) => Dispatcher.UIThread.Post(work);

    public T Send<T>(Func<T> work)
    {
        // Callers run OFF the UI thread (IPC server). On the UI thread a
        // blocking invoke would deadlock — run inline instead.
        return Dispatcher.UIThread.CheckAccess()
            ? work()
            : Dispatcher.UIThread.InvokeAsync(work).GetAwaiter().GetResult();
    }

    /// <summary>Quit the app — the Avalonia loop ends, Program returns.</summary>
    public void Exit()
        => (Application.Current?.ApplicationLifetime
            as IClassicDesktopStyleApplicationLifetime)?.Shutdown();
}


