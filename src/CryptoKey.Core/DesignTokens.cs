namespace CryptoKey;

/// <summary>
/// The single source of truth for CryptoKey's visual identity — the
/// "hardware key" design system. Platform-neutral (ARGB uints, device-
/// independent sizes) so the Avalonia app and the GDI lock screens render
/// from the same palette, spacing, and motion budget.
/// </summary>
internal static class DesignTokens
{
    // ---- Surfaces: carbon, machined layers, hairlines ----
    public const uint Carbon      = 0xFF07090C; // window background
    public const uint CarbonDeep  = 0xFF040507; // lock-screen floor, sidebar
    public const uint Surface     = 0xFF0E1218; // cards
    public const uint Raised      = 0xFF151B23; // inputs, hovered rows
    public const uint RaisedHigh  = 0xFF1C2430; // pressed / selected
    public const uint Hairline    = 0xFF232B36; // 1px borders
    public const uint HairlineHi  = 0xFF2F3946; // focused / hovered borders

    // ---- Text ----
    public const uint Text        = 0xFFEAF0F7;
    public const uint TextDim     = 0xFF8E9BAE;
    public const uint TextFaint   = 0xFF5B6778;

    // ---- Brand signal + states ----
    public const uint Signal      = 0xFF22D3EE; // interactive, verifying, focus
    public const uint SignalDeep  = 0xFF0E7490;
    public const uint Armed       = 0xFF2EE58A;
    public const uint Locked      = 0xFFFF3D57;
    public const uint Paused      = 0xFFFFB224;

    // ---- Key artwork (brushed metal) ----
    public const uint MetalHi     = 0xFF3A4555;
    public const uint MetalLo     = 0xFF161C25;
    public const uint MetalEdge   = 0xFF4B586B;

    // ---- Spacing (4pt grid) ----
    public const double S1 = 4, S2 = 8, S3 = 12, S4 = 16, S5 = 24, S6 = 32, S7 = 48;

    // ---- Radii ----
    public const double RadiusSm = 6, RadiusMd = 10, RadiusLg = 16, RadiusXl = 24;

    // ---- Type scale (px) ----
    public const double TypeCaption = 11, TypeBody = 13, TypeBodyLg = 14,
        TypeTitle = 16, TypeHeadline = 22, TypeDisplay = 40, TypeHero = 56;

    // ---- Motion (ms) ----
    public const int MotionMicro = 120, MotionStandard = 240, MotionHero = 420;

    /// <summary>State accent for a guard state — one mapping for every surface.</summary>
    public static uint ForState(GuardState state) => state switch
    {
        GuardState.Locked => Locked,
        GuardState.Paused => Paused,
        _ => Armed,
    };

    public static byte A(uint argb) => (byte)(argb >> 24);
    public static byte R(uint argb) => (byte)(argb >> 16);
    public static byte G(uint argb) => (byte)(argb >> 8);
    public static byte B(uint argb) => (byte)argb;
}
