using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Styling;
using Avalonia.Themes.Fluent;
using Avalonia.Threading;

namespace CryptoKey.Ui;

/// <summary>
/// The Avalonia application for both hosts: Fluent base + the CryptoKey
/// design system, always dark. Hosts hand in <see cref="OnReady"/>, which
/// runs on the UI thread once the platform backend is live.
/// </summary>
internal sealed class CryptoKeyApp : Application
{
    /// <summary>Set before start — runs on the UI thread when the framework is ready.</summary>
    internal static Action<CryptoKeyApp>? OnReady;

    public override void Initialize()
    {
        RequestedThemeVariant = ThemeVariant.Dark;
        Styles.Add(new FluentTheme());
        Palette.Install(Resources);
        Styles.Add(new AppStyles());
        Name = "CryptoKey";
    }

    public override void OnFrameworkInitializationCompleted()
    {
        base.OnFrameworkInitializationCompleted();
        Dispatcher.UIThread.Post(() => OnReady?.Invoke(this));
    }
}

/// <summary>Host-facing entry points for the shared UI runtime.</summary>
internal static class UiRuntime
{
    /// <summary>
    /// Runs the Avalonia loop on the calling thread until <see cref="Shutdown"/>.
    /// <paramref name="platform"/> picks the backend (Win32+Skia / Desktop).
    /// </summary>
    public static void Run(Func<AppBuilder, AppBuilder> platform, Action<CryptoKeyApp> onReady)
    {
        CryptoKeyApp.OnReady = onReady;
        try
        {
            platform(AppBuilder.Configure<CryptoKeyApp>())
                .WithInterFont()
                .StartWithClassicDesktopLifetime(Array.Empty<string>(), ShutdownMode.OnExplicitShutdown);
        }
        finally
        {
            CryptoKeyApp.OnReady = null;
        }
    }

    public static void Shutdown()
    {
        void Do() => (Application.Current?.ApplicationLifetime
            as IClassicDesktopStyleApplicationLifetime)?.Shutdown();
        if (Dispatcher.UIThread.CheckAccess())
            Do();
        else
            Dispatcher.UIThread.Post(Do);
    }

    public static void Post(Action work) => Dispatcher.UIThread.Post(work);

    /// <summary>
    /// UI-side failure policy: a dashboard bug must never take the guard down
    /// (the engine and its lock live elsewhere). Log, close the windows, keep
    /// running — the tray can reopen a fresh window.
    /// </summary>
    public static void InstallCrashPolicy(Action<string> log, Action closeWindows)
    {
        Dispatcher.UIThread.UnhandledException += (_, e) =>
        {
            try { log($"UI error (guard unaffected): {e.Exception.GetType().Name}: {e.Exception.Message}"); }
            catch (Exception) { }
            e.Handled = true;
            try { closeWindows(); }
            catch (Exception) { }
        };
    }
}
