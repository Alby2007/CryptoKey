namespace CryptoKey;

/// <summary>
/// One USB device as seen by the platform enumerator: hardware serial,
/// model string, and mounted volume paths (drive letters on Windows,
/// /Volumes mount points on macOS — where the keyfile lives).
/// </summary>
internal sealed record UsbDisk(string DeviceId, string SerialNumber, string Model, List<string> VolumePaths);
