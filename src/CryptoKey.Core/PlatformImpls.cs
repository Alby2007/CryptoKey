namespace CryptoKey;

// Shared/no-op platform impls — the Mac host and the test suite both reuse
// these (a file IS the macOS third-copy surface; the tests point it at temp).

/// <summary>Third config copy as a sibling file — macOS's plist-path backup + tests.</summary>
internal sealed class FileConfigBackup : IConfigBackup
{
    private readonly string _path;

    public FileConfigBackup(string path) => _path = path;

    public string? Read()
    {
        try { return File.Exists(_path) ? File.ReadAllText(_path) : null; }
        catch (Exception) { return null; }
    }

    public void Write(string json)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            AtomicFile.WriteAllText(_path, json);
        }
        catch (Exception) { }
    }

    public void Delete()
    {
        try { File.Delete(_path); } catch (Exception) { }
    }
}

internal sealed class NullLockPolicies : ILockPolicies
{
    public void Apply(Action<string> log) { }
    public void Restore(Action<string> log) { }
}

internal sealed class NullCaptureService : ICaptureService
{
    public void Snap(string reason, Action<string>? log = null) { }
}

internal sealed class NullCues : ICues
{
    public void Lock() { }
    public void Unlock() { }
    public void Alarm() { }
}

/// <summary>Dotfile names are already hidden — macOS keyfile attrs.</summary>
internal sealed class NoopKeyfileAttrs : IKeyfileAttrs
{
    public void Hide(string path) { }
}

/// <summary>Console-only warning presenter — the headless floor.</summary>
internal sealed class ConsoleUserAlerts : IUserAlerts
{
    public void Warn(string message) { }
}

/// <summary>Nothing post-enroll — Mac persistence is the install verb's job.</summary>
internal sealed class NoopEnrollmentExtras : IEnrollmentExtras
{
    public void AfterEnroll() { }
}

/// <summary>No mount engine — vault stays image-only where Dokany doesn't exist.</summary>
internal sealed class NullVaultMounter : IVaultMounter
{
    public bool DriverPresent => false;
    public string? DriverHint => "no vault mount driver on this platform";

    public IVaultMount? Mount(VaultVolume volume, string mountPoint, out string? error)
    {
        error = DriverHint;
        return null;
    }
}

/// <summary>
/// No TPM — vault binding is unavailable. Unwrap always fails, so a bound
/// image on a TPM-less machine can only be opened via its recovery blob.
/// </summary>
internal sealed class NullVaultTpm : IVaultTpm
{
    public static readonly NullVaultTpm Shared = new();
    public bool Available => false;
    public byte[]? WrapPepper(byte[] pepper) => null;
    public byte[]? UnwrapPepper(byte[] blob) => null;
    public void DeleteKey() { }
}
