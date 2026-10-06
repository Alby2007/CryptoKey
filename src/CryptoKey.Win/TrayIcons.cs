using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.Runtime.InteropServices;

namespace CryptoKey;

/// <summary>
/// State-colored icons rendered at runtime: rounded-square badge with a white
/// padlock glyph. Each state is a multi-resolution .ico (16–48 px PNG frames)
/// so Windows picks a crisp size for tray, taskbar, and title bar.
/// </summary>
internal sealed class TrayIcons : IDisposable
{
    private static readonly int[] Sizes = { 16, 20, 24, 32, 48 };

    // Shell icons scale past tray size (large-icon view, task switcher) —
    // the app icon exports the full PNG range up to 256.
    internal static readonly int[] ShellSizes = { 16, 20, 24, 32, 48, 64, 128, 256 };

    private readonly Dictionary<GuardState, Icon> _cache = new();
    private static Icon? _app;

    /// <summary>
    /// Brand badge (accent slate — the app.ico color, no state tint) for
    /// window title bars and alt-tab. Process-lifetime; never disposed.
    /// </summary>
    internal static Icon App
        => _app ??= new Icon(new MemoryStream(BuildIcoBytes(Theme.Accent, ShellSizes)));

    public Icon For(GuardState state)
    {
        if (!_cache.TryGetValue(state, out Icon? icon))
        {
            icon = BuildIcon(state);
            _cache[state] = icon;
        }
        return icon;
    }

    private static Icon BuildIcon(GuardState state)
    {
        Color badge = state switch
        {
            GuardState.Locked => Theme.AccentRed,
            GuardState.Paused => Theme.AccentAmber,
            _ => Theme.AccentGreen,
        };

        byte[] ico = BuildIcoBytes(badge, Sizes);
        return new Icon(new MemoryStream(ico));
    }

    /// <summary>
    /// Assembles a multi-frame ICO: ICONDIR + ICONDIRENTRY per frame + PNG
    /// data. Shared by the runtime tray cache and `--export-icon`, which
    /// writes the same bytes to app.ico for the shell-facing icon.
    /// </summary>
    internal static byte[] BuildIcoBytes(Color badge, int[] sizes)
    {
        var frames = new List<byte[]>(sizes.Length);
        foreach (int size in sizes)
        {
            using var bmp = RenderBadge(size, badge);
            using var png = new MemoryStream();
            bmp.Save(png, System.Drawing.Imaging.ImageFormat.Png);
            frames.Add(png.ToArray());
        }

        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);
        w.Write((ushort)0);                  // reserved
        w.Write((ushort)1);                  // type: icon
        w.Write((ushort)frames.Count);
        int offset = 6 + frames.Count * 16;
        for (int i = 0; i < frames.Count; i++)
        {
            int s = sizes[i];
            w.Write((byte)(s >= 256 ? 0 : s)); // width
            w.Write((byte)(s >= 256 ? 0 : s)); // height
            w.Write((byte)0);                // palette
            w.Write((byte)0);                // reserved
            w.Write((ushort)1);              // planes
            w.Write((ushort)32);             // bpp
            w.Write(frames[i].Length);
            w.Write(offset);
            offset += frames[i].Length;
        }
        foreach (byte[] frame in frames)
            w.Write(frame);
        return ms.ToArray();
    }

    /// <summary>
    /// Classic DIB-frame variant for the shell-facing app.ico: PNG-compressed
    /// frames are legal since Vista but a few icon paths still prefer the
    /// BITMAPINFOHEADER + BGRA + AND-mask layout every reader since Win95
    /// understands. Frames are bottom-up XOR pixels plus a 1bpp transparency
    /// mask; the directory says 32bpp either way.
    /// </summary>
    internal static byte[] BuildIcoBytesBmp(Color badge, int[] sizes)
    {
        var frames = new List<byte[]>(sizes.Length);
        foreach (int size in sizes)
        {
            using var bmp = RenderBadge(size, badge);
            frames.Add(BitmapToDib(bmp));
        }

        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);
        w.Write((ushort)0);                  // reserved
        w.Write((ushort)1);                  // type: icon
        w.Write((ushort)frames.Count);
        int offset = 6 + frames.Count * 16;
        for (int i = 0; i < frames.Count; i++)
        {
            int s = sizes[i];
            w.Write((byte)(s >= 256 ? 0 : s)); // width
            w.Write((byte)(s >= 256 ? 0 : s)); // height
            w.Write((byte)0);                // palette
            w.Write((byte)0);                // reserved
            w.Write((ushort)1);              // planes
            w.Write((ushort)32);             // bpp
            w.Write(frames[i].Length);
            w.Write(offset);
            offset += frames[i].Length;
        }
        foreach (byte[] frame in frames)
            w.Write(frame);
        return ms.ToArray();
    }

    /// <summary>
    /// Bitmap → .ico DIB frame: BITMAPINFOHEADER (height doubled for XOR+AND),
    /// bottom-up BGRA XOR rows, then a bottom-up 1bpp AND mask padded to 4B
    /// rows (1 = transparent).
    /// </summary>
    private static byte[] BitmapToDib(Bitmap bmp)
    {
        int size = bmp.Width;
        var data = bmp.LockBits(new Rectangle(0, 0, size, size),
            System.Drawing.Imaging.ImageLockMode.ReadOnly,
            System.Drawing.Imaging.PixelFormat.Format32bppArgb);
        int xorLen = size * size * 4;
        int andRow = ((size + 31) / 32) * 4;
        int andLen = andRow * size;
        var dib = new byte[40 + xorLen + andLen];
        try
        {
            // BITMAPINFOHEADER
            BitConverter.GetBytes(40).CopyTo(dib, 0);          // biSize
            BitConverter.GetBytes(size).CopyTo(dib, 4);        // biWidth
            BitConverter.GetBytes(size * 2).CopyTo(dib, 8);    // biHeight (XOR+AND)
            BitConverter.GetBytes((short)1).CopyTo(dib, 12);   // biPlanes
            BitConverter.GetBytes((short)32).CopyTo(dib, 14);  // biBitCount
            BitConverter.GetBytes(xorLen + andLen).CopyTo(dib, 20); // biSizeImage

            // XOR: memory is top-down B,G,R,A — same byte order as the DIB
            // wants, just flipped vertically.
            for (int y = 0; y < size; y++)
                Marshal.Copy(data.Scan0 + y * data.Stride,
                    dib, 40 + (size - 1 - y) * size * 4, size * 4);

            // AND: 1bpp bottom-up — set bit where alpha < 128.
            for (int y = 0; y < size; y++)
            {
                int row = 40 + xorLen + (size - 1 - y) * andRow;
                for (int x = 0; x < size; x++)
                {
                    byte a = dib[40 + (size - 1 - y) * size * 4 + x * 4 + 3];
                    if (a < 128)
                        dib[row + x / 8] |= (byte)(0x80 >> (x & 7));
                }
            }
        }
        finally
        {
            bmp.UnlockBits(data);
        }
        return dib;
    }

    private static Bitmap RenderBadge(int size, Color badge)
    {
        var bmp = new Bitmap(size, size);
        using var g = Graphics.FromImage(bmp);
        g.SmoothingMode = SmoothingMode.AntiAlias;

        using (var badgeBrush = new SolidBrush(badge))
        using (var path = Theme.RoundedRect(
            new RectangleF(0.5f, 0.5f, size - 1f, size - 1f), size * 0.22f))
            g.FillPath(badgeBrush, path);

        // Padlock: the Segoe Fluent lock glyph (professionally hinted, and
        // identical to the in-app iconography) rendered white on the badge.
        // Grayscale AA — ClearType color-fringes on transparent backgrounds.
        using var font = new Font(Glyphs.Family, size * 0.66f, GraphicsUnit.Pixel);
        using var center = new StringFormat
        {
            Alignment = StringAlignment.Center,
            LineAlignment = StringAlignment.Center,
        };
        g.TextRenderingHint = TextRenderingHint.AntiAlias;
        using (var lockBrush = new SolidBrush(Color.White))
            g.DrawString(Glyphs.Lock, font, lockBrush,
                new RectangleF(0, 0, size, size), center);
        return bmp;
    }

    public void Dispose()
    {
        foreach (Icon icon in _cache.Values)
            icon.Dispose();
        _cache.Clear();
    }
}
