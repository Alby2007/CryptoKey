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

/// <summary>
/// The Avalonia Application for the guard. Startup runs once the platform
/// backend is live so NSApplication/NSWindow handles exist for shielding
/// level + activation policy calls.
/// </summary>
internal sealed class MacApp : Application
{
    /// <summary>Set before AppBuilder.Start — runs on the UI thread at ready.</summary>
    internal static Action? OnStartup;

    /// <summary>
    /// 1x1 off-screen anchor: Screens enumeration needs a live TopLevel, and
    /// the tray needs a stable app window. Never visible.
    /// </summary>
    internal static Window? Anchor { get; private set; }

    public override void Initialize()
        => Styles.Add(new Avalonia.Themes.Fluent.FluentTheme());

    public override void OnFrameworkInitializationCompleted()
    {
        base.OnFrameworkInitializationCompleted();
        Anchor = new Window
        {
            Width = 1,
            Height = 1,
            Opacity = 0,
            ShowInTaskbar = false,
            SystemDecorations = SystemDecorations.None,
            Topmost = false,
            Position = new PixelPoint(-32000, -32000),
        };
        Anchor.Show();
        Dispatcher.UIThread.Post(() => OnStartup?.Invoke());
    }
}
