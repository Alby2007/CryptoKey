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
    /// <summary>Raised on the UI thread when target presence flips; arg = now present.</summary>
    public event Action<bool>? PresenceChanged;

    /// <summary>Raised on the UI thread after every check; arg = the disk, or null.</summary>
    public event Action<UsbDisk?>? PresenceChecked;

    /// <summary>Raised on the UI thread when enumeration fails — for the activity log.</summary>
    public event Action<string>? ErrorLogged;

    private const int MaxConsecutiveErrors = 3;

    private readonly System.Windows.Forms.Timer _pollTimer;
    private string _targetSerial; // settable — re-enroll retargets us live
    private bool _lastPresent;
    private int _consecutiveErrors;
    private int _checkInFlight;

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

    /// <summary>Live-adjust the poll interval. Call on the UI thread.</summary>
    public void SetPollInterval(int ms)
        => _pollTimer.Interval = Math.Clamp(ms, 250, 10_000); // match Settings slider

    /// <summary>Watch a different serial after re-enroll. Call on the UI thread.</summary>
    public void SetTargetSerial(string serial)
    {
        _targetSerial = serial;
        CheckNow();
    }

    public bool IsTargetPresent()
    {
        try
        {
            return FindDisk(_targetSerial) != null;
        }
        catch (Exception)
        {
            return false; // can't prove the key is there — callers fail closed
        }
    }

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

    // WMI runs off the UI thread — enumeration can take hundreds of ms, and
    // stalling the message loop delays the low-level keyboard hook, which is
    // exactly how keystrokes leak past the lock during a device storm.
    private void CheckNow()
    {
        if (Interlocked.Exchange(ref _checkInFlight, 1) != 0)
            return; // a check is already running — coalesce
        Task.Run(() =>
        {
            UsbDisk? disk = null;
            Exception? error = null;
            try
            {
                disk = FindDisk(_targetSerial);
            }
            catch (Exception ex)
            {
                error = ex;
            }
            try
            {
                BeginInvoke(new Action(() => ApplyCheck(disk, error)));
            }
            catch (Exception)
            {
                // Window gone — shutting down.
            }
            Interlocked.Exchange(ref _checkInFlight, 0);
        });
    }

    // Runs back on the UI thread with the enumeration result.
    private void ApplyCheck(UsbDisk? disk, Exception? error)
    {
        if (error != null)
        {
            // WMI hiccups during device storms are normal — tolerate a few,
            // then fail closed so a dead WMI service can't leave us unlocked.
            _consecutiveErrors++;
            ErrorLogged?.Invoke($"USB enumeration error #{_consecutiveErrors}: {error.Message}");
            if (_consecutiveErrors < MaxConsecutiveErrors)
                return; // transient — keep last known state
            disk = null;
        }
        else
        {
            _consecutiveErrors = 0;
        }

        bool present = disk != null;
        if (present != _lastPresent)
        {
            _lastPresent = present;
            PresenceChanged?.Invoke(present);
        }
        PresenceChecked?.Invoke(disk);
    }

    public static UsbDisk? FindDisk(string serial)
        => EnumerateUsbDisks().FirstOrDefault(d =>
            string.Equals(d.SerialNumber, serial, StringComparison.OrdinalIgnoreCase));

    public static List<UsbDisk> EnumerateUsbDisks()
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

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            _pollTimer.Dispose();
        base.Dispose(disposing);
    }
}
