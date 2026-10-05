namespace CryptoKey;

/// <summary>Segoe Fluent Icons codepoints (superset of MDL2 — same private-use range).</summary>
internal static class Glyphs
{
    public const string Lock      = "\uE72E";
    public const string Unlock    = "\uE785";
    public const string Pause     = "\uE769";
    public const string Play      = "\uE768";
    public const string Settings  = "\uE713";
    public const string Home      = "\uE80F";
    public const string Info      = "\uE946";
    public const string Warning   = "\uE7BA";
    public const string Check     = "\uE73E";
    public const string Shield    = "\uEA18";
    public const string Usb       = "\uECF1";
    public const string Key       = "\uE192";
    public const string Clock     = "\uE917";
    public const string Close     = "\uE8BB";
    public const string Minimize  = "\uE921";
    public const string Maximize  = "\uE922";
    public const string Restore   = "\uE923";
    public const string Refresh   = "\uE72C";
    public const string Hide      = "\uED1A";
    public const string Quit      = "\uE7E8";
    public const string Chevron   = "\uE70D";
    public const string Folder    = "\uE8B7";
    public const string Copy      = "\uE8C8";
    public const string Eye       = "\uE890";
    public const string EyeHide   = "\uED1A";
    public const string Activity  = "\uE9D9";
    public const string Download  = "\uE896";

    private static FontFamily? _family;

    public static FontFamily Family
        => _family ??= Try("Segoe Fluent Icons") ?? Try("Segoe MDL2 Assets") ?? new FontFamily("Segoe UI");

    public static Font Font(float size) => new(Family, size);

    private static FontFamily? Try(string name)
    {
        try { return new FontFamily(name); }
        catch (Exception) { return null; }
    }
}
