using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace CryptoKey;

/// <summary>
/// macOS lock surface: CGDisplayCapture blanks every active display and a
/// session-level CGEventTap eats all keyboard/mouse input. With a
/// <see cref="LockWindowCtl"/> it also shows the per-screen status card —
/// but input still only ever lives in the tap-side buffer; the windows
/// render dots, never characters. The invariant that matters is identical
/// to Windows: the callback runs on the tap's own run-loop thread and the
/// OS eats input at the session boundary.
///
/// Death safety: capture + taps are per-process — a killed guard releases
/// the session on its own, no dead-man's watchdog needed.
/// </summary>
internal sealed class MacLockSurface : ILockSurface
{
    public event Action<char[]>? PassphraseSubmitted;
    public event Action? PanicRequested;

    /// <summary>No foreign-desktop concept on macOS — never fires.</summary>
    public event Action<string>? SecurityEvent { add { } remove { } }

    private const int MaxPassphraseLength = 256;

    private readonly bool _devMode;
    private readonly LockWindowCtl? _ui; // null = headless tier (no windows)
    private readonly object _engageSync = new();

    private readonly char[] _buffer = new char[MaxPassphraseLength];
    private int _len;
    private DateTime _cooldownUntil = DateTime.MinValue;

    private uint[] _captured = Array.Empty<uint>();
    private Thread? _tapThread;
    private IntPtr _tapPort;         // CFMachPort — the tap
    private IntPtr _tapRunLoop;      // the tap thread's CFRunLoop
    private readonly object _tapSync = new();
    private volatile bool _engaged;
    private volatile bool _tapReady; // tap thread posted its run loop
    private volatile bool _tapAbort; // StartTap timed out — thread must not publish
    private string? _engageError;

    // The callback must be rooted — the GC can't see the CFMachPort's ref.
    private readonly MacInterop.CgEventTapCallBack _tapCallback;

    public MacLockSurface(bool devMode, LockWindowCtl? ui)
    {
        _devMode = devMode;
        _ui = ui;
        _tapCallback = OnTapEvent;
    }

    /// <summary>One tier on macOS — capture+tap can't strand a session, so
    /// it answers true to "are you the safe fallback" either way.</summary>
    public bool IsOverlay => true;

    public string? EngageError => _engageError;

    public bool Engage()
    {
        lock (_engageSync)
        {
            if (_engaged)
                return true;
            try
            {
                // Tap BEFORE capture: the cheap failure (no Accessibility
                // permission) must not blank the screens first.
                StartTap();
                CaptureAll();
                _ui?.Open();
                _engaged = true;
                _engageError = null;
                return true;
            }
            catch (Exception ex)
            {
                _engageError = ex.Message;
                ReleaseInput();
                return false;
            }
        }
    }

    public bool Disengage()
    {
        lock (_engageSync)
        {
            ReleaseInput();
            _engaged = false;
            return true; // can't strand — releasing the tap frees input
        }
    }

    /// <summary>Fail-dead path, callable from any thread.</summary>
    public void ReleaseInput()
    {
        try { KillTap(); } catch (Exception) { }
        // Windows go before capture release — a topmost fullscreen card
        // must never linger on the normal desktop.
        try { _ui?.Close(); } catch (Exception) { }
        try { ReleaseDisplays(); } catch (Exception) { }
        WipeBuffer();
    }

    public void ReassertClip() { } // no cursor confinement on this surface

    // ---------- display capture ----------

    private void CaptureAll()
    {
        var ids = new uint[16];
        if (MacInterop.CGGetActiveDisplayList((uint)ids.Length, ids, out uint count) != 0)
            throw new InvalidOperationException("CGGetActiveDisplayList failed");
        var held = new List<uint>();
        try
        {
            for (int i = 0; i < count; i++)
            {
                if (MacInterop.CGDisplayCapture(ids[i]) != 0)
                    throw new InvalidOperationException(
                        $"CGDisplayCapture failed on display {ids[i]}");
                held.Add(ids[i]);
            }
        }
        catch
        {
            foreach (uint d in held)
                MacInterop.CGDisplayRelease(d);
            throw;
        }
        _captured = held.ToArray();
    }

    private void ReleaseDisplays()
    {
        foreach (uint d in _captured)
            MacInterop.CGDisplayRelease(d);
        _captured = Array.Empty<uint>();
    }

    // ---------- event tap ----------

    private void StartTap()
    {
        _tapReady = false;
        _tapAbort = false;
        _tapThread = new Thread(TapThreadMain)
        { IsBackground = true, Name = "ck-eventtap" };
        _tapThread.Start();
        // The port is created on the run-loop thread — wait for it here so a
        // failed tap (no Accessibility permission) fails Engage synchronously.
        for (int i = 0; i < 200 && !_tapReady; i++)
            Thread.Sleep(10);
        if (!_tapReady)
        {
            // Publish-or-abort is serialized on _tapSync with the tap thread:
            // if the port was created in the race window the thread owns the
            // cleanup — a live input-eating tap must never outlive a failed
            // Engage.
            lock (_tapSync)
                _tapAbort = true;
            _tapThread.Join(1000);
            _tapThread = null;
            throw new InvalidOperationException(
                "event tap did not start — Accessibility permission missing " +
                "(System Settings → Privacy & Security → Accessibility)");
        }
        if (_tapPort == IntPtr.Zero)
            throw new InvalidOperationException("event tap port is null");
    }

    private void KillTap()
    {
        IntPtr port = _tapPort;
        IntPtr rl = _tapRunLoop;
        if (rl != IntPtr.Zero)
        {
            if (port != IntPtr.Zero)
                MacInterop.CFMachPortInvalidate(port);
            MacInterop.CFRunLoopStop(rl);
            MacInterop.CFRunLoopWakeUp(rl);
        }
        _tapPort = IntPtr.Zero;
        _tapRunLoop = IntPtr.Zero;
    }

    private void TapThreadMain()
    {
        IntPtr port = IntPtr.Zero, src = IntPtr.Zero;
        try
        {
            ulong mask = MacInterop.EventMaskFor(
                1, 2, 3, 4, 5, 6, 7, 8, 9,    // mouse down/up/drag/move/enter/exit
                MacInterop.KeyDown, MacInterop.KeyUp, MacInterop.FlagsChanged,
                22,                            // scrollWheel
                23, 24,                        // tablet point/proximity
                25, 26, 27);                   // other (middle) mouse
            port = MacInterop.CGEventTapCreate(
                MacInterop.CgSessionEventTap, MacInterop.HeadInsertEventTap,
                MacInterop.DefaultTap, mask, _tapCallback, IntPtr.Zero);
            if (port == IntPtr.Zero)
                return; // _tapReady stays false → StartTap throws
            IntPtr commonModes = MacInterop.ExportedRef(
                "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
                "kCFRunLoopCommonModes");
            src = MacInterop.CFMachPortCreateRunLoopSource(IntPtr.Zero, port, IntPtr.Zero);
            IntPtr rl = MacInterop.CFRunLoopGetCurrent();
            MacInterop.CFRunLoopAddSource(rl, src, commonModes);
            MacInterop.CGEventTapEnable(port, true);
            lock (_tapSync)
            {
                if (_tapAbort)
                    return; // timed out — finally releases port+src
                _tapPort = port;
                _tapRunLoop = rl;
                _tapReady = true;
            }
            MacInterop.CFRunLoopRun(); // returns once the port is invalidated
        }
        finally
        {
            if (src != IntPtr.Zero) MacInterop.CFRelease(src);
            if (port != IntPtr.Zero) MacInterop.CFRelease(port);
            lock (_tapSync)
            {
                _tapPort = IntPtr.Zero;
                _tapRunLoop = IntPtr.Zero;
            }
        }
    }

    // Runs on the tap thread inside the HID event path — return fast or the
    // OS re-enables us (tapDisabledByTimeout) and input leaks through.
    private IntPtr OnTapEvent(IntPtr proxy, int type, IntPtr theEvent, IntPtr refcon)
    {
        if (type is MacInterop.TapDisabledByTimeout or MacInterop.TapDisabledByUserInput)
        {
            if (_tapPort != IntPtr.Zero)
                MacInterop.CGEventTapEnable(_tapPort, true);
            return IntPtr.Zero;
        }
        if (type == MacInterop.KeyDown && theEvent != IntPtr.Zero)
            OnKey(theEvent);
        // Swallow everything — keyboard, mouse, scroll, modifiers.
        return IntPtr.Zero;
    }

    private void OnKey(IntPtr evt)
    {
        long kc = MacInterop.CGEventGetIntegerValueField(evt, MacInterop.KeyboardEventKeycode);
        ulong flags = MacInterop.CGEventGetFlags(evt);

        if (_devMode && kc == MacInterop.VkF12
            && (flags & MacInterop.FlagControl) != 0
            && (flags & MacInterop.FlagAlternate) != 0
            && (flags & MacInterop.FlagShift) != 0)
        {
            PanicRequested?.Invoke();
            return;
        }

        if (DateTime.Now < _cooldownUntil)
            return; // cooldown: keys die here, like the Windows hook

        switch (kc)
        {
            case MacInterop.VkReturn:
                if (_len == 0)
                    return; // empty Enter is noise, not a guess
                var attempt = new char[_len];
                _buffer.AsSpan(0, _len).CopyTo(attempt);
                WipeBuffer();
                _ui?.SetDots(0);
                PassphraseSubmitted?.Invoke(attempt); // subscriber owns + wipes
                return;
            case MacInterop.VkDelete:
                if (_len > 0)
                {
                    _len--;
                    _buffer[_len] = '\0';
                    _ui?.SetDots(_len);
                }
                return;
            default:
                // Unicode straight off the event — the OS already applied
                // modifiers/layout; normalize forgives the rest.
                AppendChars(evt);
                _ui?.SetDots(_len);
                return;
        }
    }

    private unsafe void AppendChars(IntPtr evt)
    {
        char* chars = stackalloc char[8];
        MacInterop.CGEventKeyboardGetUnicodeString(evt, (UIntPtr)8,
            out UIntPtr actual, (IntPtr)chars);
        int room = MaxPassphraseLength - _len;
        int take = (int)Math.Min((long)actual, room);
        for (int i = 0; i < take; i++)
        {
            char c = chars[i];
            if (!char.IsControl(c))
                _buffer[_len++] = c;
        }
        CryptographicOperations.ZeroMemory(
            MemoryMarshal.AsBytes(new Span<char>(chars, 8)));
    }

    /// <summary>Zero the whole buffer — partial input never survives.</summary>
    private void WipeBuffer()
    {
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(_buffer.AsSpan()));
        _len = 0;
    }

    // ---------- cosmetic setters → the lock windows (null-safe headless) ----------

    public void SetAnimations(bool enabled) => _ui?.SetAnimations(enabled);
    public void SetStatus(string message) => _ui?.SetStatus(message);
    public void ResetStatus() => _ui?.ResetStatus();
    public void SetPassphraseLength(int len) => _ui?.SetDots(len);
    public void SetFailedAttempts(int count) => _ui?.SetFailed(count);
    public void SetCooldown(DateTime? until)
    {
        _cooldownUntil = until ?? DateTime.MinValue;
        _ui?.SetFrozen(until);
    }

    public void Dispose()
    {
        ReleaseInput();
        _tapThread?.Join(500);
    }
}
