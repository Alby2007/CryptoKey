using System;
using System.Runtime.InteropServices;

class T
{
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CreateDesktop(string d, IntPtr dev, IntPtr dm, int f, uint a, IntPtr sa);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr OpenDesktop(string d, int f, bool inh, uint a);
    [DllImport("user32.dll", SetLastError = true)]
    static extern bool SwitchDesktop(IntPtr h);
    [DllImport("user32.dll", SetLastError = true)]
    static extern bool CloseDesktop(IntPtr h);
    [DllImport("user32.dll", SetLastError = true)]
    static extern IntPtr OpenInputDesktop(int f, bool inh, uint a);

    static int Main(string[] args)
    {
        string name = args.Length > 0 ? args[0] : "CKTestDesk";
        IntPtr hin = OpenInputDesktop(0, false, 0x0100 | 0x0040);
        Console.WriteLine($"OpenInputDesktop -> 0x{hin:X} err={Marshal.GetLastWin32Error()}");
        IntPtr h = CreateDesktop(name, IntPtr.Zero, IntPtr.Zero, 0, 0x01FF, IntPtr.Zero);
        Console.WriteLine($"CreateDesktop -> 0x{h:X} err={Marshal.GetLastWin32Error()}");
        if (h == IntPtr.Zero) return 1;
        bool ok = SwitchDesktop(h);
        Console.WriteLine($"SwitchDesktop({name}) -> {ok} err={Marshal.GetLastWin32Error()}");
        System.Threading.Thread.Sleep(1500);
        if (ok)
        {
            bool back = SwitchDesktop(hin);
            Console.WriteLine($"SwitchDesktop back -> {back} err={Marshal.GetLastWin32Error()}");
        }
        if (hin != IntPtr.Zero) CloseDesktop(hin);
        CloseDesktop(h);
        return ok ? 0 : 2;
    }
}
