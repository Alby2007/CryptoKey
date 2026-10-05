namespace CryptoKey;

/// <summary>
/// Hidden message window that watches for the enrolled USB device.
/// Reacts to WM_DEVICECHANGE broadcasts and re-checks on a 1s poll as a
/// fallback for missed events. Enumeration itself is the platform's
/// <see cref="IUsbEnumerator"/> — this is the live-monitor half.
/// </summary>
internal sealed class UsbMonitor : Form, IKeyMonitor
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
            return Platform.Services.Usb.FindDisk(_targetSerial) != null;
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
                disk = Platform.Services.Usb.FindDisk(_targetSerial);
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

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            _pollTimer.Dispose();
        base.Dispose(disposing);
    }
}
