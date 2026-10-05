using Avalonia.Controls;
using Avalonia.Platform;
using Avalonia.Threading;

namespace CryptoKey;

/// <summary>
/// Window management for the UI lock surface — one <see cref="LockWindow"/>
/// per screen at the capture-shielding level, plus the status plumbing the
/// surface's setters feed into. Every public method marshals onto the
/// Avalonia UI thread; callers run on the pump or the event-tap thread.
///
/// The controller holds the LAST state so a second window opened later
/// (screen hot-plug mid-lock) renders correctly from the start.
/// </summary>
internal sealed class LockWindowCtl
{
    private readonly List<LockWindow> _wins = new();
    private bool _open;
    private int _dots;
    private int _failed;
    private string _status = "";
    private DateTime _frozenUntil = DateTime.MinValue;
    private DispatcherTimer? _frozenTick;
    private bool _animations = true;

    // ---------- lifecycle (called by MacLockSurface) ----------

    /// <summary>Open a lock window on every screen. Call after capture.</summary>
    public void Open()
    {
        if (Dispatcher.UIThread.CheckAccess())
            DoOpen();
        else
            Dispatcher.UIThread.Post(DoOpen);
    }

    /// <summary>Close all lock windows. Call before releasing capture.</summary>
    public void Close()
    {
        if (Dispatcher.UIThread.CheckAccess())
            DoClose();
        else
            Dispatcher.UIThread.Post(DoClose);
    }

    private void DoOpen()
    {
        if (_open || MacApp.Anchor == null)
            return;
        foreach (Screen s in MacApp.Anchor.Screens.All)
        {
            var w = new LockWindow
            {
                Position = s.Bounds.Position,
                Width = s.Bounds.Width / s.Scaling,
                Height = s.Bounds.Height / s.Scaling,
            };
            w.Show();
            IntPtr nsWindow = w.TryGetPlatformHandle()?.Handle ?? IntPtr.Zero;
            if (nsWindow != IntPtr.Zero)
                MacInterop.SetShieldingLevel(nsWindow);
            _wins.Add(w);
        }
        _open = true;
        ApplyAll();
    }

    private void DoClose()
    {
        _frozenTick?.Stop();
        foreach (LockWindow w in _wins)
        {
            try { w.Close(); }
            catch (Exception) { }
        }
        _wins.Clear();
        _open = false;
    }

    // ---------- state (called by surface + GuardService setters) ----------

    public void SetDots(int len)
    {
        _dots = len;
        Apply(w => w.SetDots(len));
    }

    public void SetStatus(string status)
    {
        _status = status;
        Apply(w => w.SetStatusText(status));
    }

    public void ResetStatus()
        => SetStatus("");

    public void SetFailed(int count)
    {
        _failed = count;
        Apply(w => w.SetFailed(count));
    }

    /// <summary>Frozen input while GuardService's cooldown runs.</summary>
    public void SetFrozen(DateTime? until)
    {
        _frozenUntil = until ?? DateTime.MinValue;
        ApplyFrozen();
        if (_frozenUntil != DateTime.MinValue)
        {
            // UI-side countdown — clears itself when the freeze expires.
            _frozenTick ??= new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(500) };
            _frozenTick.Tick -= FrozenTick;
            _frozenTick.Tick += FrozenTick;
            _frozenTick.Start();
        }
    }

    public void SetAnimations(bool enabled) => _animations = enabled;

    private void FrozenTick(object? sender, EventArgs e)
    {
        if (DateTime.Now < _frozenUntil)
            return;
        _frozenUntil = DateTime.MinValue;
        _frozenTick?.Stop();
        ApplyFrozen();
    }

    // ---------- plumbing ----------

    private void ApplyFrozen()
        => Apply(w => w.SetFrozen(_frozenUntil != DateTime.MinValue));

    /// <summary>Replay the full cached state into every window.</summary>
    private void ApplyAll()
    {
        Apply(w =>
        {
            w.SetDots(_dots);
            w.SetStatusText(_status);
            w.SetFailed(_failed);
            w.SetFrozen(_frozenUntil != DateTime.MinValue);
        });
    }

    private void Apply(Action<LockWindow> act)
    {
        if (Dispatcher.UIThread.CheckAccess())
            ApplyToAll(act);
        else
            Dispatcher.UIThread.Post(() => ApplyToAll(act));
    }

    private void ApplyToAll(Action<LockWindow> act)
    {
        foreach (LockWindow w in _wins)
        {
            try { act(w); }
            catch (Exception) { }
        }
    }
}
