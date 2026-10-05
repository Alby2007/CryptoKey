using System.Security.Cryptography;
using FlashCap;

namespace CryptoKey;

/// <summary>
/// Tamper forensics: a single webcam still on security events. Fire-and-
/// forget — a snap runs on a pool thread (~1s including sensor warm-up),
/// a second request while one is in flight is dropped, and every failure
/// path ends in one quiet log line. Captures land in
/// %APPDATA%\CryptoKey\captures\ and the folder is trimmed to 50.
/// Privacy opt-in via Guard.WebcamOnTamper (default off).
/// </summary>
internal static class CaptureService
{
    private const int MaxCaptures = 50;
    private static readonly TimeSpan SnapTimeout = TimeSpan.FromSeconds(6);

    /// <summary>Protector scope tag — captures seal to this user+machine.</summary>
    internal static readonly byte[] CaptureEntropy = "CryptoKey.cap.v1"u8.ToArray();

    private static int _busy;
    private static int _unavailableLogged;

    internal static string CapturesDir => Path.Combine(ConfigStore.ConfigDir, "captures");

    /// <summary>Queue a snapshot for a tamper-flavored event. Never throws.</summary>
    public static void Snap(string reason, Action<string>? log = null)
    {
        if (Interlocked.CompareExchange(ref _busy, 1, 0) != 0)
            return; // a snap is already in flight — drop, don't queue
        _ = Task.Run(async () =>
        {
            try
            {
                var descriptor = new CaptureDevices().EnumerateDescriptors()
                    .FirstOrDefault(d => d.Characteristics.Length > 0);
                if (descriptor == null)
                {
                    LogOnce(log, "No capture device — webcam snaps unavailable.");
                    return;
                }

                // Prefer a JPEG stream (ready-made file bytes); otherwise the
                // smallest frame — a tamper snap doesn't need 1080p. YUV
                // formats are transcoded by FlashCap (transcodeIfYUV).
                var chars = descriptor.Characteristics
                    .OrderByDescending(c => c.PixelFormat == PixelFormats.JPEG)
                    .ThenBy(c => (long)c.Width * c.Height)
                    .First();

                using var cts = new CancellationTokenSource(SnapTimeout);
                byte[] image = await descriptor.TakeOneShotAsync(
                    chars, TranscodeFormats.Auto, cts.Token);
                if (image.Length == 0)
                {
                    LogOnce(log, "Capture produced no frame — snaps unavailable.");
                    return;
                }

                Directory.CreateDirectory(CapturesDir);
                string safe = string.Concat(reason.Select(
                    ch => char.IsLetterOrDigit(ch) ? ch : '-')).Trim('-');
                // Sealed at rest — .cap is a DPAPI blob; only this app on
                // this user can view it (TryOpenCapture falls back to raw
                // for legacy cleartext captures).
                string path = Path.Combine(CapturesDir,
                    $"{DateTime.Now:yyyyMMdd-HHmmss}-{safe}.cap");
                File.WriteAllBytes(path,
                    Platform.Services.Protector.Protect(image, CaptureEntropy));
                log?.Invoke($"Tamper snapshot → {path}");
                TrimCaptures();
            }
            catch (Exception ex)
            {
                LogOnce(log, $"Captures unavailable: {ex.Message}");
            }
            finally
            {
                Interlocked.Exchange(ref _busy, 0);
            }
        });
    }

    /// <summary>
    /// Read a capture for display: .cap blobs unseal through the protector;
    /// a legacy cleartext capture fails unprotect and returns raw bytes.
    /// Null when the file is missing/unreadable.
    /// </summary>
    public static byte[]? TryOpenCapture(string path)
    {
        try
        {
            byte[] blob = File.ReadAllBytes(path);
            try
            {
                return Platform.Services.Protector.Unprotect(blob, CaptureEntropy);
            }
            catch (CryptographicException)
            {
                return blob; // pre-seal cleartext capture — still viewable
            }
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static void TrimCaptures()
    {
        try
        {
            var files = new DirectoryInfo(CapturesDir).EnumerateFiles()
                .OrderByDescending(f => f.CreationTimeUtc)
                .Skip(MaxCaptures);
            foreach (var f in files)
                f.Delete();
        }
        catch (Exception) { }
    }

    /// <summary>"Unavailable" is logged once per run — a missing camera isn't a per-event error.</summary>
    private static void LogOnce(Action<string>? log, string message)
    {
        if (Interlocked.Exchange(ref _unavailableLogged, 1) == 0)
            log?.Invoke(message);
    }
}
