// Parks a real window on the CryptoKey lock desktop — a deterministic
// "squatter" for testing SecureLockSurface's engage-time eviction without
// Ctrl+Alt+Del gymnastics. While it runs, the named desktop object holds a
// foreign top-level window owned by THIS pid, exactly like a CAD-spawned
// Task Manager that survived an engagement.
//
//   dotnet run --project tools/squatter -- [desktopName]
//
// The desktop must already exist (engage the lock once to create it — or
// just run `cryptokey lock` + unlock once). Ctrl+C exits.
using System.Runtime.InteropServices;
using System.Windows.Forms;

string name = args.Length > 0 ? args[0] : "CryptoKeyLock";

// CreateDesktop reopens the existing named object; the guard holds a handle
// for process life once it has engaged once, so it exists after any lock.
IntPtr d = CreateDesktop(name, IntPtr.Zero, IntPtr.Zero, 0,
    0x000F01FF /* DESKTOP_ALL_ACCESS */, IntPtr.Zero);
if (d == IntPtr.Zero)
{
    Console.Error.WriteLine($"CreateDesktop({name}) failed err {Marshal.GetLastWin32Error()}" +
        " — engage the lock once first.");
    return;
}

// Must precede ANY window/hook on this thread. On the main thread this is
// literally the first user32 interaction — spawned threads can carry an
// inherited context that makes SetThreadDesktop fail with err 0.
if (!SetThreadDesktop(d))
{
    Console.Error.WriteLine($"SetThreadDesktop failed err {Marshal.GetLastWin32Error()}");
    return;
}
Console.WriteLine($"squatting on {name} — Ctrl+C to leave");

Application.Run(new Form
{
    Text = "squatter",
    Width = 420,
    Height = 180,
    StartPosition = FormStartPosition.Manual,
});

[DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
static extern IntPtr CreateDesktop(string lpszDesktop, IntPtr pDevMode, IntPtr pDisplay,
    uint dwFlags, uint dwDesiredAccess, IntPtr lpsa);

[DllImport("user32.dll", SetLastError = true)]
static extern bool SetThreadDesktop(IntPtr hDesktop);
