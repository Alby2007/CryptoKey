using System.Runtime.InteropServices;
using System.Text;

namespace CryptoKey;

/// <summary>
/// USB enumeration on macOS: walk /Volumes, ask DiskArbitration to resolve
/// each mount to a disk (DADiskCreateFromVolumePath → DADiskCopyBSDName),
/// then read that disk's description — removable flag + USB serial/product
/// via DADeviceProperties. That serial↔mount join is what WMI hands us free
/// on Windows — a multi-partition flash drive yields one UsbDisk with every
/// mount in VolumePaths.
/// </summary>
internal sealed class MacUsbEnumerator : IUsbEnumerator
{
    // DiskArbitration description keys (documented literal strings).
    private const string KeyMediaRemovable = "DAMediaRemovable";
    private const string KeyDeviceProps = "DADeviceProperties";
    private const string KeyMediaName = "DAMediaName";
    private const string KeyUsbSerial = "USB Serial Number";
    private const string KeyUsbProduct = "USB Product Name";

    public List<UsbDisk> Enumerate()
    {
        var bySerial = new Dictionary<string, UsbDiskAcc>(StringComparer.OrdinalIgnoreCase);
        IntPtr session = MacInterop.DASessionCreate(IntPtr.Zero);
        if (session == IntPtr.Zero)
            throw new InvalidOperationException("DASessionCreate failed");
        try
        {
            foreach (string mount in Directory.GetDirectories("/Volumes"))
            {
                try { Probe(mount, session, bySerial); }
                catch (Exception) { /* one bad mount shouldn't kill the scan */ }
            }
        }
        finally { MacInterop.CFRelease(session); }

        return bySerial.Values
            .Select(a => new UsbDisk(a.BsdName, a.Serial, a.Model, a.Volumes))
            .ToList();
    }

    /// <summary>
    /// BSD name ("disk4s1") for the disk mounted at <paramref name="mount"/>,
    /// via DADiskCreateFromVolumePath — documented API, no struct scraping.
    /// "" for /Volumes entries that aren't mount roots (the boot-volume
    /// symlink, strays) or on any DA failure.
    /// </summary>
    private static string MountToBsd(string mount, IntPtr session)
    {
        IntPtr url = IntPtr.Zero, disk = IntPtr.Zero, name = IntPtr.Zero;
        try
        {
            // CFURLCreateFromFileSystemRepresentation wants a NUL-terminated
            // UTF-8 buffer with the length NOT counting the terminator.
            byte[] path = Encoding.UTF8.GetBytes(mount + "\0");
            url = MacInterop.CFURLCreateFromFileSystemRepresentation(
                IntPtr.Zero, path, (IntPtr)(path.Length - 1), true);
            if (url == IntPtr.Zero)
                return "";
            disk = MacInterop.DADiskCreateFromVolumePath(IntPtr.Zero, session, url);
            if (disk == IntPtr.Zero)
                return "";
            name = MacInterop.DADiskCopyBSDName(disk);
            return name == IntPtr.Zero ? "" : (Marshal.PtrToStringUTF8(name) ?? "");
        }
        finally
        {
            if (name != IntPtr.Zero) MacInterop.Free(name); // malloc'd, not CF
            if (disk != IntPtr.Zero) MacInterop.CFRelease(disk);
            if (url != IntPtr.Zero) MacInterop.CFRelease(url);
        }
    }

    private static void Probe(string mount, IntPtr session,
        Dictionary<string, UsbDiskAcc> bySerial)
    {
        string bsd = MountToBsd(mount, session);
        if (bsd.Length == 0)
            return;

        IntPtr disk = IntPtr.Zero, desc = IntPtr.Zero;
        IntPtr kRemovable = IntPtr.Zero, kDeviceProps = IntPtr.Zero,
               kSerial = IntPtr.Zero, kProduct = IntPtr.Zero, kMediaName = IntPtr.Zero;
        try
        {
            disk = MacInterop.DADiskCreateFromBSDName(IntPtr.Zero, session, bsd);
            if (disk == IntPtr.Zero)
                return;
            desc = MacInterop.DADiskCopyDescription(disk);
            if (desc == IntPtr.Zero)
                return;

            kRemovable = MacInterop.CfStr(KeyMediaRemovable);
            IntPtr removable = MacInterop.CFDictionaryGetValue(desc, kRemovable);
            if (removable == IntPtr.Zero || !MacInterop.CFBooleanGetValue(removable))
                return; // internal/system volume — not a candidate key

            string serial = "", model = "";
            kDeviceProps = MacInterop.CfStr(KeyDeviceProps);
            IntPtr props = MacInterop.CFDictionaryGetValue(desc, kDeviceProps);
            if (props != IntPtr.Zero)
            {
                kSerial = MacInterop.CfStr(KeyUsbSerial);
                kProduct = MacInterop.CfStr(KeyUsbProduct);
                serial = MacInterop.CfStringToManaged(
                    MacInterop.CFDictionaryGetValue(props, kSerial))?.Trim() ?? "";
                model = MacInterop.CfStringToManaged(
                    MacInterop.CFDictionaryGetValue(props, kProduct))?.Trim() ?? "";
            }
            if (model.Length == 0)
            {
                kMediaName = MacInterop.CfStr(KeyMediaName);
                model = MacInterop.CfStringToManaged(
                    MacInterop.CFDictionaryGetValue(desc, kMediaName))?.Trim() ?? "USB device";
            }

            // Serial-blank media still enrolls (with the unreliability
            // warning) — key the group on the WHOLE-disk BSD name (strip the
            // sN partition suffix) so its partitions join.
            string key = serial.Length > 0 ? serial : "bsd:" + WholeDisk(bsd);
            if (!bySerial.TryGetValue(key, out UsbDiskAcc? acc))
                bySerial[key] = acc = new UsbDiskAcc(serial, model, bsd);
            acc.Volumes.Add(mount);
        }
        finally
        {
            foreach (IntPtr h in new[] { kRemovable, kDeviceProps, kSerial, kProduct, kMediaName })
                if (h != IntPtr.Zero) MacInterop.CFRelease(h);
            if (desc != IntPtr.Zero) MacInterop.CFRelease(desc);
            if (disk != IntPtr.Zero) MacInterop.CFRelease(disk);
        }
    }

    // "disk4s2" → "disk4" — partition suffix is a lowercase 's' + digits.
    private static string WholeDisk(string bsd)
    {
        int s = bsd.LastIndexOf('s');
        return s > 0 && int.TryParse(bsd[(s + 1)..], out _) ? bsd[..s] : bsd;
    }

    private sealed class UsbDiskAcc
    {
        public string Serial, Model, BsdName;
        public List<string> Volumes = new();
        public UsbDiskAcc(string serial, string model, string bsd)
            => (Serial, Model, BsdName) = (serial, model, bsd);
    }
}
