using System.Drawing.Drawing2D;
using System.Drawing.Text;

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
