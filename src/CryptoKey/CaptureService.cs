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

    private static int _busy;
    private static int _unavailableLogged;

    private static string CapturesDir => Path.Combine(ConfigStore.ConfigDir, "captures");

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
                string path = Path.Combine(CapturesDir,
                    $"{DateTime.Now:yyyyMMdd-HHmmss}-{safe}{SniffExt(image)}");
                File.WriteAllBytes(path, image);
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

    /// <summary>File extension from magic bytes — FlashCap may yield JPEG, PNG or BMP.</summary>
    private static string SniffExt(byte[] image)
        => image.Length >= 3 && image[0] == 0xFF && image[1] == 0xD8 ? ".jpg"
        : image.Length >= 4 && image[0] == 0x89 && image[1] == 0x50 ? ".png"
        : image.Length >= 2 && image[0] == 0x42 && image[1] == 0x4D ? ".bmp"
        : ".jpg"; // JPEG characteristics requested — assume it held

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
