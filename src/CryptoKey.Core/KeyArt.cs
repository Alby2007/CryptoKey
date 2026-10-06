namespace CryptoKey;

/// <summary>A rounded rectangle in key-art design space.</summary>
internal readonly record struct ArtRect(double X, double Y, double W, double H, double R = 0)
{
    public double CenterX => X + W / 2;
    public double CenterY => Y + H / 2;
    public double Right => X + W;
    public double Bottom => Y + H;
}

/// <summary>The key art's parts for one eject position.</summary>
internal readonly record struct KeyArtFrame(
    ArtRect Port, ArtRect Slot, ArtRect Plug, ArtRect ContactA, ArtRect ContactB,
    ArtRect Body, double LedX, double LedY, double LedR,
    double HoleX, double HoleY, double HoleR, ArtRect[] Ridges);

/// <summary>
/// Geometry of CryptoKey's signature element — a USB key seated in (or
/// ejected from) a port — in a fixed 320×140 design space. Both renderers
/// draw from this one layout: the Avalonia <c>KeyVisual</c> control and the
/// Windows GDI lock screen, so the key looks identical everywhere.
/// </summary>
internal static class KeyArt
{
    public const double Width = 320, Height = 140;

    /// <summary>How far the key slides out of the port when ejected.</summary>
    public const double EjectTravel = 64;

    /// <param name="eject">0 = fully seated, 1 = fully ejected.</param>
    /// <param name="ridges">Caller-owned scratch (length ≥3) — filled with the
    /// grip rects and returned inside the frame, so a per-frame render keeps
    /// one array for the control's life instead of allocating per call.</param>
    public static KeyArtFrame Layout(double eject, ArtRect[] ridges)
    {
        ArgumentNullException.ThrowIfNull(ridges);
        if (ridges.Length < 3)
            throw new ArgumentOutOfRangeException(nameof(ridges));
        double dx = Math.Clamp(eject, 0, 1.2) * EjectTravel;
        var port = new ArtRect(10, 26, 60, 88, 14);
        var slot = new ArtRect(44, 56, 26, 28, 5);
        var body = new ArtRect(86 + dx, 38, 168, 64, 22);
        var plug = new ArtRect(40 + dx, 58, 48, 24, 3);
        var ca = new ArtRect(plug.X + 8, plug.Y + 6, 10, 5, 1);
        var cb = new ArtRect(plug.X + 22, plug.Y + 6, 10, 5, 1);
        for (int i = 0; i < 3; i++)
            ridges[i] = new ArtRect(body.X + 96 + i * 10, body.Y + 18, 3, 28, 1.5);
        return new KeyArtFrame(port, slot, plug, ca, cb, body,
            LedX: body.X + 30, LedY: body.CenterY, LedR: 6,
            HoleX: body.X + 146, HoleY: body.CenterY, HoleR: 8,
            Ridges: ridges);
    }
}
