using System;
using System.Runtime.InteropServices;

public static class SpawnOnDesktop
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX, dwY, dwXSize, dwYSize;
        public int dwXCountChars, dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION
    {
        public IntPtr hProcess, hThread;
        public int dwProcessId, dwThreadId;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CreateProcessW(string lpApplicationName, string lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,
        uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr h);

    [StructLayout(LayoutKind.Sequential)]
    struct INPUT
    {
        public int type;
        public INPUTUNION u;
    }

    [StructLayout(LayoutKind.Explicit)]
    struct INPUTUNION
    {
        [FieldOffset(0)] public KEYBDINPUT ki;
        [FieldOffset(0)] public MOUSEINPUT mi; // pads union to real INPUT size (40B x64)
    }

    [StructLayout(LayoutKind.Sequential)]
    struct MOUSEINPUT
    {
        public int dx, dy;
        public int mouseData;
        public int dwFlags;
        public int time;
        public IntPtr dwExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct KEYBDINPUT
    {
        public short wVk;
        public short wScan;
        public int dwFlags;
        public int time;
        public IntPtr dwExtraInfo;
    }

    [DllImport("user32.dll", SetLastError = true)]
    static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);

    const ushort VK_CONTROL = 0x11, VK_MENU = 0x12, VK_SHIFT = 0x10, VK_F12 = 0x7B;
    const int INPUT_KEYBOARD = 1, KEYEVENTF_KEYUP = 0x2;

    static INPUT Key(ushort vk, bool up)
    {
        var i = new INPUT { type = INPUT_KEYBOARD };
        i.u.ki.wVk = (short)vk;
        i.u.ki.dwFlags = up ? KEYEVENTF_KEYUP : 0;
        return i;
    }

    /// <summary>Ctrl+Alt+Shift+F12 as physical key events (for the panic test).
    /// Held for 500ms — the hook reads live modifier state via GetAsyncKeyState,
    /// so releasing immediately after F12 would race the hook callback.</summary>
    public static uint PanicCombo()
    {
        var downs = new[]
        {
            Key(VK_CONTROL, false), Key(VK_MENU, false), Key(VK_SHIFT, false),
            Key(VK_F12, false),
        };
        var ups = new[]
        {
            Key(VK_F12, true),
            Key(VK_SHIFT, true), Key(VK_MENU, true), Key(VK_CONTROL, true),
        };
        uint sent = SendInput((uint)downs.Length, downs, Marshal.SizeOf(typeof(INPUT)));
        System.Threading.Thread.Sleep(500);
        sent += SendInput((uint)ups.Length, ups, Marshal.SizeOf(typeof(INPUT)));
        return sent;
    }

    public static int Run(string desktop, string commandLine, int waitMs)
    {
        var si = new STARTUPINFO { cb = Marshal.SizeOf(typeof(STARTUPINFO)), lpDesktop = desktop };
        PROCESS_INFORMATION pi;
        if (!CreateProcessW(null, commandLine, IntPtr.Zero, IntPtr.Zero, false,
                0, IntPtr.Zero, null, ref si, out pi))
            return Marshal.GetLastWin32Error();
        System.Threading.Thread.Sleep(waitMs);
        try { System.Diagnostics.Process.GetProcessById(pi.dwProcessId).Kill(); }
        catch (Exception) { }
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 0;
    }
}
