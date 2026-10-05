using System.Runtime.InteropServices;

namespace CryptoKey;

/// <summary>
/// macOS P/Invoke surface — CoreFoundation run loops, CoreGraphics event
/// tap + display capture + idle meter, Security-framework Keychain,
/// DiskArbitration volume↔device join, libc flock. Constants are fetched
/// via dlsym where they're exported variables (framework headers don't
/// guarantee the string values stay stable, symbols do).
/// </summary>
internal static class MacInterop
{
    private const string CF = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";
    private const string CG = "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics";
    private const string Sec = "/System/Library/Frameworks/Security.framework/Security";
    private const string DA = "/System/Library/Frameworks/DiskArbitration.framework/DiskArbitration";
    private const string LibC = "libc";

    // ---------- CoreFoundation ----------

    [DllImport(CF)] internal static extern IntPtr CFRunLoopGetCurrent();
    [DllImport(CF)] internal static extern void CFRunLoopRun();
    [DllImport(CF)] internal static extern void CFRunLoopStop(IntPtr rl);
    [DllImport(CF)] internal static extern void CFRunLoopWakeUp(IntPtr rl);
    [DllImport(CF)] internal static extern void CFRunLoopAddSource(IntPtr rl, IntPtr source, IntPtr mode);
    [DllImport(CF)] internal static extern IntPtr CFMachPortCreateRunLoopSource(
        IntPtr allocator, IntPtr port, IntPtr order);
    [DllImport(CF)] internal static extern void CFMachPortInvalidate(IntPtr port);
    [DllImport(CF)] internal static extern void CFRelease(IntPtr cf);

    /// <summary>kCFStringEncodingUTF8</summary>
    internal const uint CfStringUtf8 = 0x08000100;

    [DllImport(CF)] internal static extern IntPtr CFStringCreateWithCString(
        IntPtr allocator, [MarshalAs(UnmanagedType.LPUTF8Str)] string s, uint encoding);
    [DllImport(CF)] internal static extern bool CFStringGetCString(
        IntPtr s, IntPtr buffer, IntPtr bufferSize, uint encoding);
    [DllImport(CF)] internal static extern IntPtr CFStringGetCharactersPtr(IntPtr s);
    [DllImport(CF)] internal static extern IntPtr CFStringGetLength(IntPtr s);

    [DllImport(CF)] internal static extern IntPtr CFDictionaryCreateMutable(
        IntPtr allocator, IntPtr capacity, IntPtr keyCallBacks, IntPtr valueCallBacks);
    [DllImport(CF)] internal static extern void CFDictionarySetValue(
        IntPtr dict, IntPtr key, IntPtr value);
    [DllImport(CF)] internal static extern IntPtr CFDictionaryGetValue(IntPtr dict, IntPtr key);

    [DllImport(CF)] internal static extern IntPtr CFDataCreate(
        IntPtr allocator, [In] byte[] bytes, IntPtr length);
    [DllImport(CF)] internal static extern IntPtr CFDataGetBytePtr(IntPtr data);
    [DllImport(CF)] internal static extern IntPtr CFDataGetLength(IntPtr data);

    [DllImport(CF)] internal static extern bool CFBooleanGetValue(IntPtr boolean);

    [DllImport(CF)] internal static extern IntPtr CFURLCreateFromFileSystemRepresentation(
        IntPtr allocator, [In] byte[] path, IntPtr bufLen, bool isDirectory);

    /// <summary>Create a CFString caller must CFRelease.</summary>
    internal static IntPtr CfStr(string s)
        => CFStringCreateWithCString(IntPtr.Zero, s, CfStringUtf8);

    /// <summary>Get an exported CF variable (kCFBooleanTrue, kSecAttr*, kCFRunLoopCommonModes).</summary>
    internal static IntPtr ExportedRef(string library, string symbol)
    {
        IntPtr lib = NativeLibrary.Load(library);
        IntPtr addr = NativeLibrary.GetExport(lib, symbol);
        return Marshal.ReadIntPtr(addr); // symbol IS a variable holding the ref
    }

    /// <summary>Address of an exported struct constant (e.g. kCFTypeDictionaryKeyCallBacks).</summary>
    internal static IntPtr ExportedAddr(string library, string symbol)
        => NativeLibrary.GetExport(NativeLibrary.Load(library), symbol);

    /// <summary>
    /// CFDictionary with the real type callbacks. NULL callbacks give
    /// pointer-equality keys — SecItem* then fails to find kSecClass by
    /// content and returns errSecParam.
    /// </summary>
    internal static IntPtr CfDict(params IntPtr[] keyVals)
    {
        IntPtr dict = CFDictionaryCreateMutable(IntPtr.Zero, (IntPtr)(keyVals.Length / 2),
            ExportedAddr(CF, "kCFTypeDictionaryKeyCallBacks"),
            ExportedAddr(CF, "kCFTypeDictionaryValueCallBacks"));
        for (int i = 0; i + 1 < keyVals.Length; i += 2)
            CFDictionarySetValue(dict, keyVals[i], keyVals[i + 1]);
        return dict;
    }

    internal static string? CfStringToManaged(IntPtr s)
    {
        if (s == IntPtr.Zero)
            return null;
        IntPtr chars = CFStringGetCharactersPtr(s);
        if (chars != IntPtr.Zero)
            return Marshal.PtrToStringUni(chars, (int)CFStringGetLength(s));
        // No direct char pointer — fall back to the C-string copy.
        IntPtr size = (IntPtr)(4 * ((int)CFStringGetLength(s) + 1));
        IntPtr buf = Marshal.AllocHGlobal(size);
        try
        {
            return CFStringGetCString(s, buf, size, CfStringUtf8)
                ? Marshal.PtrToStringUTF8(buf)
                : null;
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    internal static byte[] CfDataToBytes(IntPtr data)
    {
        int len = (int)CFDataGetLength(data);
        var bytes = new byte[len];
        Marshal.Copy(CFDataGetBytePtr(data), bytes, 0, len);
        return bytes;
    }

    // ---------- CoreGraphics: event tap ----------

    // CGEventTapLocation
    internal const int CgSessionEventTap = 1;
    // CGEventTapPlacement
    internal const int HeadInsertEventTap = 0;
    // CGEventTapOptions — defaultTap = active filter (can eat events)
    internal const int DefaultTap = 0;

    internal delegate IntPtr CgEventTapCallBack(
        IntPtr proxy, int type, IntPtr theEvent, IntPtr refcon);

    [DllImport(CG)] internal static extern IntPtr CGEventTapCreate(
        int tap, int place, int options, ulong eventsOfInterest,
        CgEventTapCallBack callback, IntPtr userInfo);
    [DllImport(CG)] internal static extern void CGEventTapEnable(IntPtr tap, bool enable);
    [DllImport(CG)] internal static extern ulong CGEventGetFlags(IntPtr theEvent);
    [DllImport(CG)] internal static extern long CGEventGetIntegerValueField(
        IntPtr theEvent, int field);
    [DllImport(CG)] internal static extern void CGEventKeyboardGetUnicodeString(
        IntPtr theEvent, UIntPtr maxStringLength, out UIntPtr actualStringLength,
        IntPtr unicodeString);

    // CGEventType
    internal const int KeyDown = 10;
    internal const int KeyUp = 11;
    internal const int FlagsChanged = 12;
    internal const int TapDisabledByTimeout = unchecked((int)0xFFFFFFFE);
    internal const int TapDisabledByUserInput = unchecked((int)0xFFFFFFFF);

    // CGEventField
    internal const int KeyboardEventKeycode = 9;

    // CGEventFlags masks
    internal const ulong FlagShift = 0x00020000;
    internal const ulong FlagControl = 0x00040000;
    internal const ulong FlagAlternate = 0x00080000; // Option
    internal const ulong FlagCommand = 0x00100000;
    internal const ulong FlagCapsLock = 0x00010000;

    // macOS virtual keycodes
    internal const int VkReturn = 36;
    internal const int VkDelete = 51;   // Backspace
    internal const int VkF12 = 111;

    internal static ulong EventMaskFor(params int[] types)
    {
        ulong mask = 0;
        foreach (int t in types)
            mask |= 1UL << t;
        return mask;
    }

    // ---------- CoreGraphics: displays + idle ----------

    [DllImport(CG)] internal static extern int CGGetActiveDisplayList(
        uint maxDisplays, [Out] uint[] activeDisplays, out uint displayCount);
    [DllImport(CG)] internal static extern int CGDisplayCapture(uint display);
    [DllImport(CG)] internal static extern int CGDisplayRelease(uint display);
    [DllImport(CG)] internal static extern int CGReleaseAllDisplays();
    [DllImport(CG)] internal static extern int CGShieldingWindowLevel();

    /// <summary>Seconds since last HID input — the macOS GetLastInputInfo.</summary>
    [DllImport(CG)] internal static extern double CGEventSourceSecondsSinceLastEventType(
        int stateID, uint eventType);

    internal const int HidSystemState = 1;      // kCGEventSourceStateHIDSystemState
    internal const uint AnyInputEvent = ~0u;    // kCGAnyInputEventType

    // ---------- Security framework (Keychain) ----------

    [DllImport(Sec)] internal static extern int SecItemAdd(IntPtr attributes, IntPtr result);
    [DllImport(Sec)] internal static extern int SecItemCopyMatching(IntPtr query, out IntPtr result);
    [DllImport(Sec)] internal static extern int SecItemDelete(IntPtr query);
    [DllImport(Sec)] internal static extern int SecItemUpdate(IntPtr query, IntPtr attributesToUpdate);

    internal const int ErrSecSuccess = 0;
    internal const int ErrSecItemNotFound = -25300;

    // ---------- DiskArbitration ----------
    // NB: CFAllocatorRef is the FIRST parameter on all DA create calls.

    [DllImport(DA)] internal static extern IntPtr DASessionCreate(IntPtr allocator);
    [DllImport(DA)] internal static extern IntPtr DADiskCreateFromBSDName(
        IntPtr allocator, IntPtr session,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string name);
    [DllImport(DA)] internal static extern IntPtr DADiskCopyDescription(IntPtr disk);

    // ---------- libc ----------

    // struct statfs offsets (identical on x86_64 + arm64):
    //   f_fstypename[16]  @ 72
    //   f_mntonname[1024] @ 88
    //   f_mntfromname[1024] @ 1112   ("/dev/disk4s1")
    internal const int StatfsBufSize = 4096;
    internal const int StatfsMntFromOff = 1112;

    [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint = "statfs$INODE64",
        SetLastError = true)]
    internal static extern int StatFs(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string path, [Out] byte[] buf);

    [DllImport(LibC, SetLastError = true)] internal static extern int open(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags, int mode);
    [DllImport(LibC, SetLastError = true)] internal static extern int flock(int fd, int operation);
    [DllImport(LibC)] internal static extern int close(int fd);
    [DllImport(LibC)] internal static extern int unlink(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string path);

    internal const int O_WRONLY = 0x0001;
    internal const int O_CREAT = 0x0200;
    internal const int O_CLOEXEC = 0x1000000;
    internal const int LOCK_EX = 2;
    internal const int LOCK_NB = 4;
    internal const int EWOULDBLOCK = 35;

    // ---------- Objective-C runtime (NSWindow level, activation policy) ----------

    private const string ObjC = "/usr/lib/libobjc.A.dylib";

    [DllImport(ObjC)] internal static extern IntPtr objc_getClass(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string name);
    [DllImport(ObjC)] internal static extern IntPtr sel_registerName(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string name);
    [DllImport(ObjC, EntryPoint = "objc_msgSend")]
    internal static extern IntPtr ObjcMsgSend(IntPtr receiver, IntPtr selector);
    [DllImport(ObjC, EntryPoint = "objc_msgSend")]
    internal static extern IntPtr ObjcMsgSendLong(IntPtr receiver, IntPtr selector, long arg);

    internal static IntPtr Sel(string name) => sel_registerName(name);

    /// <summary>Put an NSWindow at the capture-shielding level.</summary>
    internal static void SetShieldingLevel(IntPtr nsWindow)
    {
        ObjcMsgSendLong(nsWindow, Sel("setLevel:"), CGShieldingWindowLevel());
        // canJoinAllSpaces — the lock card must not be stranded on another Space.
        ObjcMsgSendLong(nsWindow, Sel("setCollectionBehavior:"), 1);
    }

    /// <summary>NSApplicationActivationPolicyAccessory — daemon, no Dock icon.</summary>
    internal static void HideFromDock()
    {
        IntPtr app = ObjcMsgSend(objc_getClass("NSApplication"), Sel("sharedApplication"));
        if (app != IntPtr.Zero)
            ObjcMsgSendLong(app, Sel("setActivationPolicy:"), 1);
    }
}
