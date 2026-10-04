using System.Drawing.Drawing2D;

namespace CryptoKey;

/// <summary>
/// State-colored icons rendered at runtime: rounded-square badge with a white
/// padlock glyph. Each state is a multi-resolution .ico (16–48 px PNG frames)
/// so Windows picks a crisp size for tray, taskbar, and title bar.
/// </summary>
internal sealed class TrayIcons : IDisposable
{
    private static readonly int[] Sizes = { 16, 20, 24, 32, 48 };

    private readonly Dictionary<GuardState, Icon> _cache = new();

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

        var frames = new List<byte[]>(Sizes.Length);
        foreach (int size in Sizes)
        {
            using var bmp = RenderBadge(size, badge);
            using var png = new MemoryStream();
            bmp.Save(png, System.Drawing.Imaging.ImageFormat.Png);
            frames.Add(png.ToArray());
        }

        // Assemble a multi-frame ICO: ICONDIR + ICONDIRENTRY per frame + PNG data.
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);
        w.Write((ushort)0);                  // reserved
        w.Write((ushort)1);                  // type: icon
        w.Write((ushort)frames.Count);
        int offset = 6 + frames.Count * 16;
        for (int i = 0; i < frames.Count; i++)
        {
            int s = Sizes[i];
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
        ms.Position = 0;
        return new Icon(ms);
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

        // Padlock: shackle arc + legs, rounded body, keyhole.
        float shackleW = size * 0.40f;
        float shackleX = (size - shackleW) / 2f;
        float shackleTop = size * 0.16f;
        using var shacklePen = new Pen(Color.White, Math.Max(1f, size * 0.075f));
        g.DrawArc(shacklePen, shackleX, shackleTop, shackleW, shackleW, 180, 180);
        float legTop = shackleTop + shackleW / 2f;
        float legBottom = size * 0.52f;
        g.DrawLine(shacklePen, shackleX, legTop, shackleX, legBottom);
        g.DrawLine(shacklePen, shackleX + shackleW, legTop, shackleX + shackleW, legBottom);

        using (var bodyBrush = new SolidBrush(Color.White))
        using (var body = Theme.RoundedRect(
            new RectangleF(size * 0.26f, size * 0.47f, size * 0.48f, size * 0.36f),
            size * 0.06f))
            g.FillPath(bodyBrush, body);

        float kh = size * 0.10f;
        using (var holeBrush = new SolidBrush(badge))
            g.FillEllipse(holeBrush, (size - kh) / 2f, size * 0.58f, kh, kh);
        return bmp;
    }

    public void Dispose()
    {
        foreach (Icon icon in _cache.Values)
            icon.Dispose();
        _cache.Clear();
    }
}
