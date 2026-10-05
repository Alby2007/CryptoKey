using DokanNet;
using DokanNet.Logging;

namespace CryptoKey;

/// <summary>
/// The Windows mount engine — wraps Dokany's user-mode driver. Presence is
/// checked honestly: a missing driver means mounts can never succeed, so the
/// Vault page shows an install-needed state instead of a fake mount.
/// </summary>
internal sealed class DokanVaultMounter : IVaultMounter
{
    private readonly Action<string>? _log;
    private static bool _driverAbsentLogged;

    public DokanVaultMounter(Action<string>? log = null) => _log = log;

    public bool DriverPresent
    {
        get
        {
            // Failure is retried every check — installing Dokany mid-session
            // gets picked up on the next verify/mount attempt.
            try
            {
                using var dokan = new Dokan(new NullLogger());
                return dokan.DriverVersion > 0;
            }
            catch (Exception)
            {
                return false;
            }
        }
    }

    public string? DriverHint =>
        "needs the Dokany driver — dokan-dev.github.io (install, then retry)";

    public IVaultMount? Mount(VaultVolume volume, string mountPoint, out string? error)
    {
        error = null;
        if (!DriverPresent)
        {
            error = DriverHint;
            if (!_driverAbsentLogged)
            {
                _driverAbsentLogged = true;
                _log?.Invoke("Vault mount requested but the Dokany driver is not installed.");
            }
            return null;
        }
        try
        {
            return new DokanMount(volume, mountPoint, _log);
        }
        catch (DokanException ex)
        {
            error = $"mount failed: {ex.ErrorStatus}";
            return null;
        }
        catch (Exception ex)
        {
            error = $"mount failed: {ex.Message}";
            return null;
        }
    }
}

/// <summary>
/// A live Dokan mount: the filesystem thread parks in
/// <see cref="DokanInstance.WaitForFileSystemClosed"/> until dismount.
/// Dispose force-unmounts — holders see I/O errors, by design.
/// </summary>
internal sealed class DokanMount : IVaultMount
{
    private readonly Dokan _dokan;
    private readonly DokanInstance _instance;
    private readonly Thread _waiter;

    public string MountPoint { get; }
    public event Action? Detached;

    public DokanMount(VaultVolume volume, string mountPoint, Action<string>? log)
    {
        // "V:" → "V:\" — DOKAN_OPTIONS wants the rooted form.
        string mp = mountPoint.TrimEnd('\\').TrimEnd('/');
        if (mp.Length < 2 || !char.IsLetter(mp[0]) || mp[1] != ':')
            mp = "V:";
        MountPoint = mp;

        _dokan = new Dokan(new NullLogger());
        var fs = new DokanVaultFileSystem(volume, log);
        _instance = new DokanInstanceBuilder(_dokan)
            .ConfigureLogger(() => new NullLogger())
            .ConfigureOptions(o =>
            {
                o.MountPoint = MountPoint + "\\";
                o.Options = DokanOptions.FixedDrive | DokanOptions.MountManager;
                o.TimeOut = TimeSpan.FromSeconds(20);
            })
            .Build(fs); // throws DokanException on mount failure — driver-level

        _waiter = new Thread(WaitLoop)
        {
            IsBackground = true,
            Name = "CryptoKey.Vault",
        };
        _waiter.Start();
    }

    private void WaitLoop()
    {
        try
        {
            _instance.WaitForFileSystemClosed(uint.MaxValue);
        }
        catch (Exception) { }
        Detached?.Invoke();
    }

    /// <summary>Force-dismount: driver detach → thread exit → instance teardown.</summary>
    public void Dispose()
    {
        try { _dokan.RemoveMountPoint(MountPoint + "\\"); } catch (Exception) { }
        try { _dokan.Unmount(MountPoint[0]); } catch (Exception) { }
        try { if (!_waiter.Join(5000)) _instance.Dispose(); } catch (Exception) { }
        try { _instance.Dispose(); } catch (Exception) { }
        try { _dokan.Dispose(); } catch (Exception) { }
    }
}
