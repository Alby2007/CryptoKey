using System.Runtime.InteropServices;
using System.Text;

namespace CryptoKey;

/// <summary>
/// Swallows all keyboard/mouse input via low-level hooks while active.
/// The keyboard hook feeds a failsafe passphrase buffer before eating each
/// keystroke, so typing the passphrase still works while input is "blocked".
/// </summary>
internal sealed class InputLocker : IDisposable
{
    /// <summary>Current length of the passphrase buffer (for masked feedback).</summary>
    public event Action<int>? PassphraseLengthChanged;

    /// <summary>Raised when the user presses Enter; argument is the buffered passphrase.</summary>
    public event Action<string>? PassphraseSubmitted;

    /// <summary>Dev-mode emergency exit combo (Ctrl+Alt+Shift+F12).</summary>
    public event Action? PanicRequested;

    private const int MaxPassphraseLength = 256;

    private readonly bool _devMode;
    private readonly StringBuilder _buffer = new();
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
        _buffer.Clear();
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
    /// Freeze passphrase input until the given time — the hook keeps
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
        _buffer.Clear();
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
                        string attempt = _buffer.ToString();
                        _buffer.Clear();
                        PassphraseLengthChanged?.Invoke(0);
                        PassphraseSubmitted?.Invoke(attempt);
                        break;
                    case NativeMethods.VK_BACK:
                        if (_buffer.Length > 0)
                            _buffer.Length--;
                        PassphraseLengthChanged?.Invoke(_buffer.Length);
                        break;
                    case NativeMethods.VK_CAPITAL:
                        _capsOn = !_capsOn;
                        break;
                    case NativeMethods.VK_NUMLOCK:
                        _numOn = !_numOn;
                        break;
                    default:
                        string? chars = VkToChars(kbd.vkCode, kbd.scanCode);
                        if (chars != null && _buffer.Length < MaxPassphraseLength)
                        {
                            int room = MaxPassphraseLength - _buffer.Length;
                            _buffer.Append(chars.Length <= room ? chars : chars[..room]);
                            PassphraseLengthChanged?.Invoke(_buffer.Length);
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
    private string? VkToChars(uint vk, uint scan)
    {
        var state = new byte[256];
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

        var sb = new StringBuilder(8);
        uint flags = ModifierDown(NativeMethods.VK_MENU) ? 1u : 0u;
        int result = NativeMethods.ToUnicode(vk, scan, state, sb, sb.Capacity, flags);
        if (result <= 0)
            return null;

        var chars = new StringBuilder(result);
        for (int i = 0; i < result; i++)
        {
            if (!char.IsControl(sb[i]))
                chars.Append(sb[i]);
        }
        return chars.Length == 0 ? null : chars.ToString();
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
