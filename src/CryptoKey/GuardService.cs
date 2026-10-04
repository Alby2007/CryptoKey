namespace CryptoKey;

/// <summary>
/// State machine: key absent -> locked; key present -> verify serial +
/// keyfile hash -> unlocked. Locks immediately if the key is absent (or
/// fails verification) at startup.
/// </summary>
internal sealed class GuardService : IDisposable
{
    private readonly KeyConfig _config;
    private readonly UsbMonitor _monitor;
    private readonly InputLocker _input;
    private readonly LockScreen _lock;
    private bool _locked;

    public GuardService(KeyConfig config, bool devMode)
    {
        _config = config;
        _monitor = new UsbMonitor(config.DeviceSerial);
        _input = new InputLocker(devMode);
        _lock = new LockScreen();

        _monitor.PresenceChanged += OnPresenceChanged;
        _input.PassphraseSubmitted += OnPassphraseSubmitted;
        _input.PassphraseLengthChanged += len => _lock.SetPassphraseLength(len);
        _input.PanicRequested += () =>
        {
            Log("Panic combo (Ctrl+Alt+Shift+F12) — exiting.");
            Application.Exit();
        };
    }

    public void Start()
    {
        Log("Guard started.");
        if (_monitor.IsTargetPresent() && KeyVerifier.Verify(_config, out string detail))
            Log($"Key verified at startup ({detail}) — unlocked.");
        else
            LockNow();
    }

    private void OnPresenceChanged(object? sender, EventArgs e)
    {
        if (_monitor.IsTargetPresent())
        {
            if (!_locked)
                return;
            if (KeyVerifier.Verify(_config, out string detail))
                UnlockNow();
            else
                Log($"Key arrived but verification failed: {detail} — staying locked.");
        }
        else if (!_locked)
        {
            LockNow();
        }
    }

    private void OnPassphraseSubmitted(string attempt)
    {
        if (ConfigStore.VerifyPassphrase(_config, attempt))
            UnlockNow();
        else
            _lock.SetStatus("Incorrect passphrase — try again.");
    }

    private void LockNow()
    {
        if (_locked)
            return;
        _locked = true;
        Log("LOCKED — key absent.");
        _input.Lock();
        _lock.ResetStatus();
        _lock.Show();
    }

    private void UnlockNow()
    {
        if (!_locked)
            return;
        _locked = false;
        Log("Unlocked.");
        _input.Unlock();
        _lock.Hide();
    }

    private static void Log(string message)
        => Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] {message}");

    public void Dispose()
    {
        _input.Dispose();
        _lock.Dispose();
        _monitor.Dispose();
    }
}
