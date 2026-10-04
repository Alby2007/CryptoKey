using System.Management;

namespace CryptoKey;

internal sealed record UsbDisk(string DeviceId, string SerialNumber, string Model, List<string> DriveLetters);

/// <summary>
/// Hidden message window that watches for the enrolled USB device.
/// Reacts to WM_DEVICECHANGE broadcasts and re-checks on a 1s poll as a
/// fallback for missed events.
/// </summary>
internal sealed class UsbMonitor : Form
{
    /// <summary>Raised on the UI thread whenever target-device presence flips.</summary>
    public event EventHandler? PresenceChanged;

    private readonly System.Windows.Forms.Timer _pollTimer;
    private readonly string _targetSerial;
    private bool _lastPresent;

    public UsbMonitor(string targetSerial)
    {
        _targetSerial = targetSerial;

        // Hidden top-level window: never shown, but its handle receives broadcasts.
        FormBorderStyle = FormBorderStyle.None;
        ShowInTaskbar = false;
        StartPosition = FormStartPosition.Manual;
        Location = new Point(-32000, -32000);
        Size = new Size(1, 1);
        _ = Handle;

        _lastPresent = IsTargetPresent();

        _pollTimer = new System.Windows.Forms.Timer { Interval = 1000 };
        _pollTimer.Tick += (_, _) => CheckNow();
        _pollTimer.Start();
    }

    public bool IsTargetPresent() => FindDisk(_targetSerial) != null;

    protected override void WndProc(ref Message m)
    {
        if (m.Msg == NativeMethods.WM_DEVICECHANGE)
        {
            int evt = m.WParam.ToInt32();
            if (evt is NativeMethods.DBT_DEVICEARRIVAL or NativeMethods.DBT_DEVICEREMOVECOMPLETE)
                CheckNow();
        }
        base.WndProc(ref m);
    }

    private void CheckNow()
    {
        bool present = IsTargetPresent();
        if (present != _lastPresent)
        {
            _lastPresent = present;
            PresenceChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    public static UsbDisk? FindDisk(string serial)
        => EnumerateUsbDisks().FirstOrDefault(d =>
            string.Equals(d.SerialNumber, serial, StringComparison.OrdinalIgnoreCase));

    public static List<UsbDisk> EnumerateUsbDisks()
    {
        var disks = new List<UsbDisk>();
        using var searcher = new ManagementObjectSearcher(
            "SELECT DeviceID, SerialNumber, Model FROM Win32_DiskDrive WHERE InterfaceType='USB'");
        foreach (ManagementObject drive in searcher.Get())
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
        foreach (ManagementObject assoc in searcher.Get())
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

        using (var searcher = new ManagementObjectSearcher(
                   "SELECT Antecedent, Dependent FROM Win32_LogicalDiskToPartition"))
        foreach (ManagementObject assoc in searcher.Get())
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

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            _pollTimer.Dispose();
        base.Dispose(disposing);
    }
}
