using System.Runtime.InteropServices;
using System.Text;

namespace CryptoKey;

/// <summary>
/// Write-tmp-then-rename with the durability gap closed. A bare
/// WriteAll*+Move can leave a renamed-but-empty file when power or the
/// USB drive goes away mid-write — the data sits in cache and never
/// reaches media (FAT32/exFAT have no journal to cover it). Flushing to
/// the device before the rename guarantees the moved-in file is whole:
/// FlushFileBuffers on Windows, fcntl(F_FULLFSYNC) on macOS (plain fsync
/// there only hits the drive cache — it lies about the device flush).
/// </summary>
internal static class AtomicFile
{
    public static void WriteAllBytes(string path, byte[] data)
    {
        string tmp = path + ".tmp";
        try
        {
            using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                fs.Write(data);
                FlushToDevice(fs);
            }
            File.Move(tmp, path, overwrite: true);
        }
        catch
        {
            try { File.Delete(tmp); } catch { }
            throw;
        }
    }

    public static void WriteAllText(string path, string text)
        => WriteAllBytes(path, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false).GetBytes(text));

    private static void FlushToDevice(FileStream fs)
    {
        if (OperatingSystem.IsMacOS())
        {
            // Runtime-gated rather than #if — Core is single-target; the
            // fcntl P/Invoke is only ever called on macOS.
            if (fcntl(fs.SafeFileHandle.DangerousGetHandle(), F_FULLFSYNC) != 0)
                fs.Flush(true); // fcntl refused — fsync is still the floor
        }
        else
        {
            fs.Flush(true);
        }
    }

    private const int F_FULLFSYNC = 51;

    [DllImport("libc", SetLastError = true)]
    private static extern int fcntl(IntPtr fd, int cmd);
}
