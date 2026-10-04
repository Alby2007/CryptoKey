using System.Drawing.Drawing2D;

namespace CryptoKey;

/// <summary>
/// State-colored tray icons rendered at runtime: rounded-square badge with a
/// white padlock glyph. One icon per GuardState, cached; underlying HICONs are
/// destroyed on dispose.
/// </summary>
internal sealed class TrayIcons : IDisposable
{
    private const int Size = 32;

    private readonly Dictionary<GuardState, (Icon Icon, IntPtr Handle)> _cache = new();

    public Icon For(GuardState state)
    {
        if (!_cache.TryGetValue(state, out var entry))
        {
            entry = Render(state);
            _cache[state] = entry;
        }
        return entry.Icon;
    }

    private static (Icon, IntPtr) Render(GuardState state)
    {
        Color badge = state switch
        {
            GuardState.Locked => Theme.AccentRed,
            GuardState.Paused => Theme.AccentAmber,
            _ => Theme.AccentGreen,
        };

        using var bmp = new Bitmap(Size, Size);
        using (var g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;

            using (var badgeBrush = new SolidBrush(badge))
            using (var path = RoundedRect(0.5f, 0.5f, Size - 1f, Size - 1f, Size * 0.22f))
                g.FillPath(badgeBrush, path);

            // Padlock: shackle arc + legs, rounded body, keyhole.
            float shackleW = Size * 0.40f;
            float shackleX = (Size - shackleW) / 2f;
            float shackleTop = Size * 0.16f;
            using var shacklePen = new Pen(Color.White, Size * 0.075f);
            g.DrawArc(shacklePen, shackleX, shackleTop, shackleW, shackleW, 180, 180);
            float legTop = shackleTop + shackleW / 2f;
            float legBottom = Size * 0.52f;
            g.DrawLine(shacklePen, shackleX, legTop, shackleX, legBottom);
            g.DrawLine(shacklePen, shackleX + shackleW, legTop, shackleX + shackleW, legBottom);

            using (var bodyBrush = new SolidBrush(Color.White))
            using (var body = RoundedRect(Size * 0.26f, Size * 0.47f, Size * 0.48f, Size * 0.36f, Size * 0.06f))
                g.FillPath(bodyBrush, body);

            float kh = Size * 0.10f;
            using (var holeBrush = new SolidBrush(badge))
                g.FillEllipse(holeBrush, (Size - kh) / 2f, Size * 0.58f, kh, kh);
        }

        IntPtr hIcon = bmp.GetHicon();
        return (Icon.FromHandle(hIcon), hIcon);
    }

    private static GraphicsPath RoundedRect(float x, float y, float w, float h, float r)
    {
        var p = new GraphicsPath();
        float d = r * 2f;
        p.AddArc(x, y, d, d, 180, 90);
        p.AddArc(x + w - d, y, d, d, 270, 90);
        p.AddArc(x + w - d, y + h - d, d, d, 0, 90);
        p.AddArc(x, y + h - d, d, d, 90, 90);
        p.CloseFigure();
        return p;
    }

    public void Dispose()
    {
        foreach ((Icon icon, IntPtr handle) in _cache.Values)
        {
            icon.Dispose();
            NativeMethods.DestroyIcon(handle);
        }
        _cache.Clear();
    }
}
