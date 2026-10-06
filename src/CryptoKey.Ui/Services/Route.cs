namespace CryptoKey.Ui;

/// <summary>
/// Typed navigation targets — the tray, the IPC `open` verb, and in-app
/// links all name a page by route, never by tab index (an index drifted
/// once already: the old tray "Settings…" opened the Vault tab).
/// </summary>
internal enum Route
{
    Home,
    Key,
    Vault,
    Protection,
    Alerts,
    Activity,
    General,
    About,
}

internal static class Routes
{
    public static readonly Route[] Primary =
        { Route.Home, Route.Key, Route.Vault, Route.Protection, Route.Alerts, Route.Activity };

    public static readonly Route[] Secondary = { Route.General, Route.About };

    public static string Title(Route r) => r switch
    {
        Route.Home => "Home",
        Route.Key => "Key & Recovery",
        Route.Vault => "Vault",
        Route.Protection => "Protection",
        Route.Alerts => "Alerts & Evidence",
        Route.Activity => "Activity",
        Route.General => "General",
        Route.About => "About",
        _ => r.ToString(),
    };

    public static string Icon(Route r) => r switch
    {
        Route.Home => IconData.Home,
        Route.Key => IconData.Key,
        Route.Vault => IconData.Vault,
        Route.Protection => IconData.Shield,
        Route.Alerts => IconData.Bell,
        Route.Activity => IconData.Activity,
        Route.General => IconData.Settings,
        Route.About => IconData.Info,
        _ => IconData.Info,
    };

    /// <summary>Parses an IPC `open [route]` argument; unknown/absent → Home.</summary>
    public static Route Parse(string? arg)
        // IsDefined: TryParse accepts numerics, so "open 99" would produce
        // an unnamed route otherwise.
        => Enum.TryParse(arg, ignoreCase: true, out Route r) && Enum.IsDefined(r) ? r
            : arg?.ToLowerInvariant() switch
            {
                "settings" => Route.General,
                "security" => Route.Key,
                _ => Route.Home,
            };
}
