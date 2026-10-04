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

    private readonly bool _devMode;
    private readonly StringBuilder _buffer = new();

    private IntPtr _kbHook = IntPtr.Zero;
    private IntPtr _mouseHook = IntPtr.Zero;

    // Delegate references must stay alive for the lifetime of the hooks.
    private NativeMethods.HookProc? _kbProc;
    private NativeMethods.HookProc? _mouseProc;

    public InputLocker(bool devMode) => _devMode = devMode;

    public bool Active => _kbHook != IntPtr.Zero;

    public void Lock()
    {
        if (Active)
            return;
        IntPtr hMod = NativeMethods.GetModuleHandle(null);
        _kbProc = KeyboardHook;
        _mouseProc = MouseHook;
        _kbHook = NativeMethods.SetWindowsHookEx(NativeMethods.WH_KEYBOARD_LL, _kbProc, hMod, 0);
        _mouseHook = NativeMethods.SetWindowsHookEx(NativeMethods.WH_MOUSE_LL, _mouseProc, hMod, 0);
        ClipCursor();
        _buffer.Clear();
        PassphraseLengthChanged?.Invoke(0);
    }

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
                    default:
                        char? c = VkToChar(kbd.vkCode, kbd.scanCode);
                        if (c != null)
                        {
                            _buffer.Append(c.Value);
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

    private static char? VkToChar(uint vk, uint scan)
    {
        var state = new byte[256];
        if (!NativeMethods.GetKeyboardState(state))
            return null;
        var sb = new StringBuilder(8);
        int result = NativeMethods.ToUnicode(vk, scan, state, sb, sb.Capacity, 0);
        if (result == 1 && !char.IsControl(sb[0]))
            return sb[0];
        return null;
    }
}
