using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace CryptoKey;

/// <summary>
/// Swallows all keyboard/mouse input via low-level hooks while active.
/// The keyboard hook feeds a recovery-phrase buffer before eating each
/// keystroke, so typing the phrase still works while input is "blocked".
///
/// Memory hygiene: the phrase accumulates in a fixed char[] — never a
/// string/StringBuilder, so no GC copies of partial input can linger. On
/// submit the used region is copied to a fresh char[] and the buffer is
/// wiped; the submitted array is the subscriber's to wipe after verify.
/// </summary>
internal sealed class InputLocker : IDisposable
{
    /// <summary>Current length of the phrase buffer (for masked feedback).</summary>
    public event Action<int>? PassphraseLengthChanged;

    /// <summary>Raised when the user presses Enter; argument is the buffered
    /// phrase in a char[] the subscriber must wipe after use.</summary>
    public event Action<char[]>? PassphraseSubmitted;

    /// <summary>Dev-mode emergency exit combo (Ctrl+Alt+Shift+F12).</summary>
    public event Action? PanicRequested;

    private const int MaxPassphraseLength = 256;

    private readonly bool _devMode;
    private readonly char[] _buffer = new char[MaxPassphraseLength];
    private int _len;
    // Per-hook reusable scratch — kept alive so keystrokes allocate nothing.
    // Hook callbacks are single-threaded (the pumping thread), so reuse is safe.
    private readonly char[] _scratch = new char[8];
    private readonly byte[] _keyState = new byte[256];
    private bool _capsOn;
    private bool _numOn;
    private DateTime _cooldownUntil = DateTime.MinValue;

    private IntPtr _kbHook = IntPtr.Zero;
    private IntPtr _mouseHook = IntPtr.Zero;

    // Delegate references must stay alive for the lifetime of the hooks.
    private NativeMethods.HookProc? _kbProc;
    private NativeMethods.HookProc? _mouseProc;

    public InputLocker(bool devMode) => _devMode = devMode;

    public bool Active => _kbHook != IntPtr.Zero && _mouseHook != IntPtr.Zero;

    /// <summary>Install hooks and clip the cursor. False if either hook failed.</summary>
    public bool Lock()
    {
        if (Active)
            return true;
        IntPtr hMod = NativeMethods.GetModuleHandle(null);
        _kbProc = KeyboardHook;
        _mouseProc = MouseHook;
        _kbHook = NativeMethods.SetWindowsHookEx(NativeMethods.WH_KEYBOARD_LL, _kbProc, hMod, 0);
        _mouseHook = NativeMethods.SetWindowsHookEx(NativeMethods.WH_MOUSE_LL, _mouseProc, hMod, 0);
        if (_kbHook == IntPtr.Zero || _mouseHook == IntPtr.Zero)
        {
            RemoveHooks();
            return false;
        }
        ClipCursor();
        WipeBuffer();
        _cooldownUntil = DateTime.MinValue;
        _capsOn = ToggledOn(NativeMethods.VK_CAPITAL);
        _numOn = ToggledOn(NativeMethods.VK_NUMLOCK);
        PassphraseLengthChanged?.Invoke(0);
        return true;
    }

    /// <summary>Re-apply the cursor clip — other processes can clear it.</summary>
    public void ReassertClip()
    {
        if (Active)
            ClipCursor();
    }

    /// <summary>
    /// Freeze phrase input until the given time — the hook keeps
    /// swallowing keystrokes but never buffers or submits them, so mashing
    /// during a cooldown can't stack the penalty. Null clears it.
    /// </summary>
    public void SetCooldownUntil(DateTime? until)
        => _cooldownUntil = until ?? DateTime.MinValue;

    public void Unlock() => RemoveHooks();

    public void Dispose() => RemoveHooks();

    private void RemoveHooks()
    {
        if (_kbHook != IntPtr.Zero)
        {
            NativeMethods.UnhookWindowsHookEx(_kbHook);
            _kbHook = IntPtr.Zero;
        }
        if (_mouseHook != IntPtr.Zero)
        {
            NativeMethods.UnhookWindowsHookEx(_mouseHook);
            _mouseHook = IntPtr.Zero;
        }
        NativeMethods.ClipCursor(IntPtr.Zero);
        WipeBuffer();
    }

    /// <summary>Zero the whole buffer — partial input never survives.</summary>
    private void WipeBuffer()
    {
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(_buffer));
        _len = 0;
    }

    private static void ClipCursor()
    {
        var rect = new NativeMethods.RECT { Left = 0, Top = 0, Right = 1, Bottom = 1 };
        NativeMethods.ClipCursor(ref rect);
    }

    private IntPtr KeyboardHook(int nCode, IntPtr wParam, IntPtr lParam)
    {
        if (nCode >= 0)
        {
            int msg = wParam.ToInt32();
            if (msg is NativeMethods.WM_KEYDOWN or NativeMethods.WM_SYSKEYDOWN)
            {
                var kbd = Marshal.PtrToStructure<NativeMethods.KBDLLHOOKSTRUCT>(lParam);
                int vk = (int)kbd.vkCode;

                if (_devMode && vk == NativeMethods.VK_F12
                    && ModifierDown(NativeMethods.VK_CONTROL)
                    && ModifierDown(NativeMethods.VK_MENU)
                    && ModifierDown(NativeMethods.VK_SHIFT))
                {
                    PanicRequested?.Invoke();
                    return (IntPtr)1;
                }

                // Cooldown: keys die here — no buffer, no Enter, no counting.
                if (DateTime.Now < _cooldownUntil)
                    return (IntPtr)1;

                switch (vk)
                {
                    case NativeMethods.VK_RETURN:
                        // An empty Enter is noise, not a guess — don't burn
                        // a backoff attempt on it.
                        if (_len == 0)
                            break;
                        // The subscriber owns this copy — it's wiped after
                        // verify, while our buffer is wiped now.
                        var attempt = new char[_len];
                        _buffer.AsSpan(0, _len).CopyTo(attempt);
                        WipeBuffer();
                        PassphraseLengthChanged?.Invoke(0);
                        PassphraseSubmitted?.Invoke(attempt);
                        break;
                    case NativeMethods.VK_BACK:
                        if (_len > 0)
                        {
                            _len--;
                            _buffer[_len] = '\0';
                        }
                        PassphraseLengthChanged?.Invoke(_len);
                        break;
                    case NativeMethods.VK_CAPITAL:
                        _capsOn = !_capsOn;
                        break;
                    case NativeMethods.VK_NUMLOCK:
                        _numOn = !_numOn;
                        break;
                    default:
                        int chars = VkToChars(kbd.vkCode, kbd.scanCode);
                        if (chars > 0)
                        {
                            int room = MaxPassphraseLength - _len;
                            int take = Math.Min(chars, room);
                            if (take > 0)
                            {
                                _scratch.AsSpan(0, take).CopyTo(_buffer.AsSpan(_len));
                                _len += take;
                                PassphraseLengthChanged?.Invoke(_len);
                            }
                            CryptographicOperations.ZeroMemory(
                                MemoryMarshal.AsBytes(_scratch));
                        }
                        break;
                }
            }
            return (IntPtr)1; // swallow everything
        }
        return NativeMethods.CallNextHookEx(_kbHook, nCode, wParam, lParam);
    }

    private IntPtr MouseHook(int nCode, IntPtr wParam, IntPtr lParam)
        => nCode >= 0 ? (IntPtr)1 : NativeMethods.CallNextHookEx(_mouseHook, nCode, wParam, lParam);

    private static bool ModifierDown(int vk)
        => (NativeMethods.GetAsyncKeyState(vk) & 0x8000) != 0;

    // Modifier state is built from GetAsyncKeyState rather than
    // GetKeyboardState, which only reflects this thread's message queue and
    // goes stale when the lock form isn't foreground. Toggle keys (Caps/Num
    // Lock) are tracked in the hook itself — every press passes through here,
    // so our flags can't drift from what the user sees. Dead keys are left
    // pending (ToUnicode returns <0) and compose with the next stroke — which
    // is also why multi-char results are appended whole.
    private int VkToChars(uint vk, uint scan)
    {
        byte[] state = _keyState;
        Array.Clear(state);
        SetDown(state, NativeMethods.VK_SHIFT);
        SetDown(state, NativeMethods.VK_CONTROL);
        SetDown(state, NativeMethods.VK_MENU);
        SetDown(state, NativeMethods.VK_LSHIFT);
        SetDown(state, NativeMethods.VK_RSHIFT);
        SetDown(state, NativeMethods.VK_LCONTROL);
        SetDown(state, NativeMethods.VK_RCONTROL);
        SetDown(state, NativeMethods.VK_LMENU);
        SetDown(state, NativeMethods.VK_RMENU);
        if (_capsOn)
            state[NativeMethods.VK_CAPITAL] = 0x01;
        if (_numOn)
            state[NativeMethods.VK_NUMLOCK] = 0x01;

        uint flags = ModifierDown(NativeMethods.VK_MENU) ? 1u : 0u;
        int result = NativeMethods.ToUnicode(vk, scan, state, _scratch, _scratch.Length, flags);
        if (result == 0)
            return 0;
        if (result < 0)
        {
            // Dead key — left pending inside ToUnicode to compose with the
            // next stroke; the accent char it echoed is wiped.
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(_scratch));
            return 0;
        }

        // Compact non-control chars to the front; the caller copies
        // _scratch[..count] into the buffer and wipes the scratch.
        int useful = 0;
        for (int i = 0; i < result && i < _scratch.Length; i++)
        {
            char c = _scratch[i];
            if (!char.IsControl(c))
                _scratch[useful++] = c;
        }
        if (useful == 0)
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(_scratch));
        return useful;
    }

    private static void SetDown(byte[] state, int vk)
    {
        if (ModifierDown(vk))
            state[vk] = 0x80;
    }

    // Best-effort seed for toggle keys — a wrong guess self-corrects on the
    // next press, since every press is tracked in the hook from then on.
    private static bool ToggledOn(int vk)
        => (NativeMethods.GetAsyncKeyState(vk) & 0x0001) != 0;
}
