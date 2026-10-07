using Avalonia;
using Avalonia.Controls;

namespace CryptoKey.Ui;

/// <summary>Services every page gets from the shell.</summary>
internal sealed class PageContext
{
    public required GuardClient Client { get; init; }
    public required IUiHost Host { get; init; }
    public required Action<string, bool> Toast { get; init; }
    public required Action<Route> Navigate { get; init; }
    public required Func<Window?> Owner { get; init; }
    public required Action OpenOnboarding { get; init; }
    public required Action<Action<bool>, AuthMode?> ShowAuth { get; init; }

    public PlatformCapabilities Caps => Host.Capabilities;
}

/// <summary>
/// Base for routed pages: lives in the shell's cache, subscribes to guard
/// events only while on screen, and refreshes on every appearance.
/// </summary>
internal abstract class Page : UserControl
{
    protected PageContext Ctx { get; }
    protected GuardClient Client => Ctx.Client;

    protected Page(PageContext ctx) => Ctx = ctx;

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        Client.StateChanged += OnState;
        Client.SettingsChanged += OnSettings;
        Refresh();
    }

    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnDetachedFromVisualTree(e);
        Client.StateChanged -= OnState;
        Client.SettingsChanged -= OnSettings;
        OnHidden();
    }

    private void OnState(StatusSnapshot _) => Refresh();
    private void OnSettings(SettingsView _) => Refresh();

    /// <summary>Re-render from <see cref="GuardClient.Snapshot"/> / <see cref="GuardClient.Settings"/>.</summary>
    public abstract void Refresh();

    /// <summary>Page left the screen — clear sensitive fields here.</summary>
    protected virtual void OnHidden() { }

    /// <summary>Toast the error if any; returns true on success.</summary>
    protected bool Report(string? error, string? success = null)
    {
        if (error != null)
        {
            Ctx.Toast(error, true);
            return false;
        }
        if (success != null)
            Ctx.Toast(success, false);
        return true;
    }

    /// <summary>Map a dispatch reply to <see cref="Report"/>'s error slot.</summary>
    protected static string? ReplyError(string reply)
        => reply.StartsWith("ok", StringComparison.Ordinal) ? null
            : reply.StartsWith("err ", StringComparison.Ordinal)
                ? reply[4..] : reply;

    /// <summary>
    /// AUTH_REQUIRED means the session (or the fresh-auth window for
    /// destructive verbs) lapsed — offer the sign-in face and re-invoke
    /// <paramref name="retry"/> when it succeeds. Returns true when the
    /// retry was handed off; the caller must NOT also report the reply.
    /// </summary>
    protected bool RetryAfterAuth(string reply, Action retry)
    {
        if (!reply.Contains("AUTH_REQUIRED", StringComparison.Ordinal))
            return false;
        Ctx.ShowAuth(ok => { if (ok) retry(); }, AuthMode.SignIn);
        return true;
    }

    protected GuardSettings G => Client.Settings.Guard;

    /// <summary>Persist a settings change through the single engine-thread write path.</summary>
    protected async void Save(Action<GuardSettings> mutate, string? success = null)
        => Report(await Client.UpdateSettings(mutate), success);
}
