using System.Text;

namespace CryptoKey;

/// <summary>
/// Write-tmp-then-rename with the durability gap closed. A bare
/// WriteAll*+Move can leave a renamed-but-empty file when power or the
/// USB drive goes away mid-write — the data sits in cache and never
/// reaches media (FAT32/exFAT have no journal to cover it). Flush(true)
/// is FlushFileBuffers: it pushes the bytes to the device before the
/// rename, so the moved-in file is guaranteed whole.
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
                fs.Flush(true);
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
}
