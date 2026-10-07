using Avalonia;
using Avalonia.Headless;
using Avalonia.Threading;
using CryptoKey.Tests;

[assembly: AvaloniaTestApplication(typeof(CryptoKey.Ui.Tests.TestAppBuilder))]

namespace CryptoKey.Ui.Tests;

public static class TestAppBuilder
{
    public static AppBuilder BuildAvaloniaApp() => AppBuilder.Configure<CryptoKeyApp>()
        .UseHeadless(new AvaloniaHeadlessPlatformOptions());
}

/// <summary>Host stand-in: every capability on, no real shell side effects.</summary>
internal sealed class FakeHost : IUiHost
{
    public PlatformCapabilities Capabilities { get; init; } = new("Windows",
        true, true, true, true, true, true, true, true);
    public bool OsPrefersReducedMotion => false;
    public bool IsElevated => false;
    public string VersionText => "v0.0.0-test";
    public UiStartupMode Startup { get; set; }
    public List<string> Opened { get; } = new();

    public Stream TrayIcon(GuardState state) => new MemoryStream();
    public Stream AppIcon() => new MemoryStream();
    public (int X, int Y)? CursorPosition() => null;
    public void OpenFolder(string path) => Opened.Add(path);
    public void RevealFile(string path) => Opened.Add(path);
    public void OpenUrl(string url) => Opened.Add(url);
    public UiStartupMode GetStartupMode() => Startup;
    public Task<string?> SetStartupModeAsync(UiStartupMode mode, Action<string> progress)
    {
        Startup = mode;
        return Task.FromResult<string?>(null);
    }
    public bool ShortcutExists(UiShortcut which) => false;
    public void SetShortcut(UiShortcut which, bool enabled) { }
    public string? StartElevatedInstance() => "not in tests";
    public string CapturesDir => Path.GetTempPath();
    public void TestCamera(Action<string> log) { }
    public CaptureInfo LatestCapture(bool webcamEnabled) => new(null, "none");
    public void MainWindowVisibilityChanged(bool visible) { }
}

internal static class Harness
{
    /// <summary>A real GuardService over the null test platform, wrapped like the app does.</summary>
    public static (GuardService Service, GuardClient Client, KeyConfig Config) Guard(
        Action<KeyConfig>? configure = null)
    {
        KeyConfig cfg = TestDisk.NewConfig(TestDisk.RandomSecret());
        // Runs BEFORE the GuardService/client see the config — the client's
        // first Snapshot() already reflects it (the dormant-state tests need
        // exactly that ordering).
        configure?.Invoke(cfg);
        var svc = new GuardService(cfg, devMode: false, forceClassic: false);
        var client = new GuardClient(svc, cfg, devMode: false, a => Dispatcher.UIThread.Post(a));
        return (svc, client, cfg);
    }

    public static PageContext Context(GuardClient client, IUiHost? host = null) => new()
    {
        Client = client,
        Host = host ?? new FakeHost(),
        Toast = (_, _) => { },
        Navigate = _ => { },
        Owner = () => null,
        OpenOnboarding = () => { },
        ShowAuth = (_, _) => { },
    };

    /// <summary>Run the UI dispatcher for real time — timers fire, posts drain.</summary>
    public static void Pump(TimeSpan duration)
    {
        // A nested main-loop frame runs timers AND posted jobs on real time;
        // RunJobs alone drains the queue but never fires DispatcherTimers.
        using var cts = new CancellationTokenSource(duration);
        Dispatcher.UIThread.MainLoop(cts.Token);
        Dispatcher.UIThread.RunJobs();
    }
}
