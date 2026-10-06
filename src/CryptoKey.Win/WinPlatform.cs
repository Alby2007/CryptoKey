using System.IO.Pipes;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Win32;

namespace CryptoKey;

/// <summary>
/// The Windows platform bundle — every Core seam bound to its Win32/WinForms
/// implementation. Registered by <see cref="Program.Main"/> before anything
/// touches Core.
/// </summary>
internal static class WinPlatform
{
    public static PlatformServices Services => new()
    {
        Paths = new WinPaths(),
        Protector = new DpapiProtector(),
        Usb = new WmiUsbEnumerator(),
        KeyMonitors = new WinKeyMonitorFactory(),
        Ipc = new WinIpcSecurity(),
        SingleInstance = new MutexSingleInstance(),
        StopSignals = new WinStopSignals(),
        LockPolicies = new WinLockPolicies(),
        Capture = new WinCaptureService(),
        SystemActions = new WinSystemActions(),
        ConfigBackup = new RegistryConfigBackup(),
        KeyfileAttrs = new WinKeyfileAttrs(),
        AppLifetime = new WinAppLifetime(),
        Surfaces = new WinLockSurfaceFactory(),
        EnrollmentExtras = new WinEnrollmentExtras(),
        UserAlerts = new WinUserAlerts(),
        Cues = new WinCues(),
        VaultMounts = new DokanVaultMounter(),
        VaultTpm = new WinVaultTpm(),
        Capabilities = Capabilities,
    };

    public static PlatformCapabilities Capabilities { get; } = new("Windows",
        Vault: true, Tpm: true, Webcam: true, PrivateDesktop: true, LockPolicies: true,
        Elevation: true, Shortcuts: true, StartupAtLogin: true);
}

internal sealed class WinPaths : IPlatformPaths
{
    public string ConfigDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "CryptoKey");
}

/// <summary>DPAPI, CurrentUser scope — the keyfile envelope dies off this user+machine.</summary>
internal sealed class DpapiProtector : IKeyProtector
{
    public byte[] Protect(byte[] data, byte[] entropy)
        => ProtectedData.Protect(data, entropy, DataProtectionScope.CurrentUser);

    public byte[] Unprotect(byte[] data, byte[] entropy)
        => ProtectedData.Unprotect(data, entropy, DataProtectionScope.CurrentUser);
}

/// <summary>WMI disk enumeration — the same queries UsbMonitor ran inline.</summary>
internal sealed class WmiUsbEnumerator : IUsbEnumerator
{
    public List<UsbDisk> Enumerate()
    {
        var disks = new List<UsbDisk>();
        using var searcher = new ManagementObjectSearcher(
            "SELECT DeviceID, SerialNumber, Model FROM Win32_DiskDrive " +
            "WHERE InterfaceType='USB' OR MediaType LIKE 'Removable%' OR MediaType LIKE 'External%'");
        using var results = searcher.Get();
        foreach (ManagementObject drive in results)
        {
            using (drive)
            {
                string deviceId = (drive["DeviceID"] as string ?? "").Trim();
                string serial = (drive["SerialNumber"] as string ?? "").Trim();
                string model = (drive["Model"] as string ?? "").Trim();
                disks.Add(new UsbDisk(deviceId, serial, model, DriveLettersForDisk(deviceId)));
            }
        }
        return disks;
    }

    // Win32_DiskDrive ("\\.\PHYSICALDRIVE2")
    //   -> Win32_DiskDriveToDiskPartition -> Win32_DiskPartition ("Disk #2, Partition #0")
    //   -> Win32_LogicalDiskToPartition   -> Win32_LogicalDisk  ("E:")
    private static List<string> DriveLettersForDisk(string deviceId)
    {
        var letters = new List<string>();
        var partitionIds = new List<string>();

        using (var searcher = new ManagementObjectSearcher(
                   "SELECT Antecedent, Dependent FROM Win32_DiskDriveToDiskPartition"))
        {
            using var results = searcher.Get();
            foreach (ManagementObject assoc in results)
            {
                using (assoc)
                {
                    string? diskId = ExtractDeviceId(assoc["Antecedent"]?.ToString());
                    if (string.Equals(diskId, deviceId, StringComparison.OrdinalIgnoreCase))
                    {
                        string? partId = ExtractDeviceId(assoc["Dependent"]?.ToString());
                        if (partId != null)
                            partitionIds.Add(partId);
                    }
                }
            }
        }

        using (var searcher = new ManagementObjectSearcher(
                   "SELECT Antecedent, Dependent FROM Win32_LogicalDiskToPartition"))
        {
            using var results = searcher.Get();
            foreach (ManagementObject assoc in results)
            {
                using (assoc)
                {
                    string? partId = ExtractDeviceId(assoc["Antecedent"]?.ToString());
                    if (partId != null && partitionIds.Contains(partId, StringComparer.OrdinalIgnoreCase))
                    {
                        string? letter = ExtractDeviceId(assoc["Dependent"]?.ToString());
                        if (letter != null)
                            letters.Add(letter);
                    }
                }
            }
        }

        return letters;
    }

    // Association paths look like:
    //   \\HOST\root\cimv2:Win32_DiskDrive.DeviceID="\\\\.\\PHYSICALDRIVE2"
    // The quoted DeviceID has each backslash doubled, so unescape before comparing.
    private static string? ExtractDeviceId(string? assocPath)
    {
        if (assocPath == null)
            return null;
        const string marker = "DeviceID=\"";
        int start = assocPath.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (start < 0)
            return null;
        start += marker.Length;
        int end = assocPath.IndexOf('"', start);
        return end > start ? assocPath[start..end].Replace("\\\\", "\\") : null;
    }
}

/// <summary>WinForms marshal — Post = BeginInvoke, Send = Invoke.</summary>
internal sealed class ControlDispatcher : IUiDispatcher
{
    private readonly Control _control;
    public ControlDispatcher(Control control) => _control = control;

    public void Post(Action work)
    {
        _control.BeginInvoke(work);
    }

    // A null result is legitimate (e.g. a UI query whose success value is a
    // null error string) — pass it through rather than throwing.
    public T Send<T>(Func<T> work) => (T)_control.Invoke(work)!;
}

/// <summary>The monitor is itself a Form — it doubles as the dispatch control.</summary>
internal sealed class WinKeyMonitorFactory : IKeyMonitorFactory
{
    public KeyMonitorHandle Create(string targetSerial)
    {
        var monitor = new UsbMonitor(targetSerial);
        return new KeyMonitorHandle(monitor, new ControlDispatcher(monitor));
    }
}

/// <summary>
/// Pipe ACLs. Two layers: the SACL's Medium integrity label lets the normal
/// (medium-IL) CLI reach an *elevated* guard — MIC no-write-up would
/// otherwise block it — while the DACL scopes access to the owning user.
/// The pipe lives in the global namespace, so a World DACL would let any
/// other session on the machine send pause/lock/quit.
/// </summary>
internal sealed class WinIpcSecurity : IIpcSecurity
{
    public bool Elevated
        => new WindowsPrincipal(WindowsIdentity.GetCurrent())
            .IsInRole(WindowsBuiltInRole.Administrator);

    public NamedPipeServerStream CreatePipe(out bool integrityLabeled)
    {
        string sid = WindowsIdentity.GetCurrent().User?.Value ?? "WD";

        // Applying a SACL needs SE_SECURITY_PRIVILEGE — non-elevated guards
        // can't set the integrity label, and don't need it: a medium-IL pipe
        // is reachable by medium clients by default. Elevated guards must
        // have it or the normal CLI can't write, so try SACL first and fall
        // back to DACL-only.
        try
        {
            var security = new PipeSecurity();
            security.SetSecurityDescriptorSddlForm($"D:(A;;GA;;;{sid})S:(ML;;NW;;;ME)");
            integrityLabeled = true;
            return Create(security);
        }
        catch (Exception)
        {
            var security = new PipeSecurity();
            security.SetSecurityDescriptorSddlForm($"D:(A;;GA;;;{sid})");
            integrityLabeled = false;
            return Create(security);
        }

        static NamedPipeServerStream Create(PipeSecurity security)
            => NamedPipeServerStreamAcl.Create(
                IpcServer.PipeName, PipeDirection.InOut,
                NamedPipeServerStream.MaxAllowedServerInstances,
                PipeTransmissionMode.Byte, PipeOptions.Asynchronous,
                0, 0, security, HandleInheritability.None);
    }
}

/// <summary>Named kernel mutex — process death releases it, which is the point.</summary>
internal sealed class MutexSingleInstance : ISingleInstance
{
    private const int TakeoverWaitSeconds = 30;

    public IDisposable? Acquire(string name, bool waitForRelease)
    {
        string full = @"Local\" + name;
        var deadline = DateTime.UtcNow.AddSeconds(TakeoverWaitSeconds);
        do
        {
            var m = new Mutex(true, full, out bool createdNew);
            if (createdNew)
                return m;
            m.Dispose();
            if (waitForRelease)
                Thread.Sleep(250);
        }
        while (waitForRelease && DateTime.UtcNow < deadline);
        return null;
    }

    public bool IsHeld(string name)
    {
        if (Mutex.TryOpenExisting(@"Local\" + name, out Mutex? m))
        {
            m.Dispose();
            return true;
        }
        return false;
    }
}

/// <summary>A named manual-reset event: Set = stand down, Reset = armed.</summary>
internal sealed class WinStopSignals : IStopSignalFactory
{
    private static string FullName => @"Local\" + Watchdog.StopEventName;

    public IStopSignalWaiter OpenWaiter()
        => new Waiter(new EventWaitHandle(false, EventResetMode.ManualReset, FullName));

    public void Reset()
    {
        using var e = new EventWaitHandle(false, EventResetMode.ManualReset, FullName);
        e.Reset();
    }

    public void Signal()
    {
        using var e = EventWaitHandle.OpenExisting(FullName);
        e.Set();
    }

    private sealed class Waiter : IStopSignalWaiter
    {
        private readonly EventWaitHandle _e;
        public Waiter(EventWaitHandle e) => _e = e;
        public bool Wait(int ms) => _e.WaitOne(ms);
        public void Dispose() => _e.Dispose();
    }
}

internal sealed class WinLockPolicies : ILockPolicies
{
    public void Apply(Action<string> log) => LockPolicies.Apply(log);
    public void Restore(Action<string> log) => LockPolicies.Restore(log);
}

internal sealed class WinCaptureService : ICaptureService
{
    public void Snap(string reason, Action<string>? log = null)
        => CaptureService.Snap(reason, log);
}

internal sealed class WinSystemActions : ISystemActions
{
    public void LockScreen() => NativeMethods.LockWorkStation();

    public uint IdleMilliseconds() => NativeMethods.IdleMilliseconds();

    public void ReleaseInputDesktop()
    {
        try
        {
            IntPtr h = NativeMethods.OpenDesktop("Default", 0, false,
                NativeMethods.DESKTOP_SWITCHDESKTOP);
            if (h != IntPtr.Zero)
            {
                NativeMethods.SwitchDesktop(h);
                NativeMethods.CloseDesktop(h);
            }
        }
        catch (Exception) { }
    }
}

/// <summary>
/// Third config copy in HKCU — a folder wipe can't reach the registry, a
/// registry delete can't reach the folder. Same trust bar as .bak.
/// </summary>
internal sealed class RegistryConfigBackup : IConfigBackup
{
    internal const string KeyPath = @"Software\CryptoKey";
    private const string ValueName = "Config";

    public string? Read()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(KeyPath);
            return key?.GetValue(ValueName) as string;
        }
        catch (Exception)
        {
            return null;
        }
    }

    public void Write(string json)
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(KeyPath);
            key.SetValue(ValueName, json);
        }
        catch (Exception) { }
    }

    public void Delete()
    {
        try { Registry.CurrentUser.DeleteSubKeyTree(KeyPath, throwOnMissingSubKey: false); }
        catch (Exception) { }
    }
}

internal sealed class WinKeyfileAttrs : IKeyfileAttrs
{
    public void Hide(string path)
        => File.SetAttributes(path, FileAttributes.Hidden | FileAttributes.System);
}

internal sealed class WinAppLifetime : IAppLifetime
{
    public void Exit() => Application.Exit();
}

internal sealed class WinLockSurfaceFactory : ILockSurfaceFactory
{
    public ILockSurface Create(bool securePreferred, bool devMode)
        => securePreferred
            ? new SecureLockSurface(devMode)
            : new ClassicLockSurface(devMode);
}

internal sealed class WinEnrollmentExtras : IEnrollmentExtras
{
    public void AfterEnroll()
    {
        ShortcutManager.SetEnabled(ShortcutTarget.StartMenu, true);
        ShortcutManager.SetEnabled(ShortcutTarget.Desktop, true);
        Console.WriteLine("Shortcuts created: Start Menu + Desktop.");
    }
}

/// <summary>Modal warning for paths with no console reader (autostart launches).</summary>
internal sealed class WinUserAlerts : IUserAlerts
{
    public void Warn(string message)
        => MessageBox.Show(message, "CryptoKey",
            MessageBoxButtons.OK, MessageBoxIcon.Warning);
}

/// <summary>Synthesized WAV cues — the SoundPlayer lives in the Windows host.</summary>
internal sealed class WinCues : ICues
{
    public void Lock() => Sounds.Lock();
    public void Unlock() => Sounds.Unlock();
    public void Alarm() => Sounds.Alarm();
}
