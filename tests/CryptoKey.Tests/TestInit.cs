using System.Runtime.CompilerServices;
using Xunit;

// The suite shares one redirected config dir + one registry key — classes
// must not race each other's Saves/Loads.
[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace CryptoKey.Tests;

/// <summary>
/// Redirect ConfigStore's root into a per-run temp dir before ANY test
/// code runs. ConfigDir is static-readonly — first touch wins — and every
/// crypto test reaches ConfigStore through statics (CreateNew, MatchSecret,
/// RotateSecret), so a collection fixture would race test ordering. A
/// module initializer has no ordering hazard.
///
/// The assert fails the whole run loudly if production ever stops honoring
/// the variable — the failure mode that once wrote test data into the
/// real user profile.
/// </summary>
internal static class TestInit
{
    public static string Dir { get; } = Path.Combine(
        Path.GetTempPath(), "ckcfg-" + Guid.NewGuid().ToString("N"));

    [ModuleInitializer]
    public static void RedirectConfigRoot()
    {
        Environment.SetEnvironmentVariable("CRYPTOKEY_CONFIG_ROOT", Dir);
        if (!ConfigStore.ConfigDir.StartsWith(Dir, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                $"Config root redirect failed — got {ConfigStore.ConfigDir}");

        // Same redirect for the registry copy — otherwise every Save/
        // CreateNew in a test writes into the user's real HKCU backup
        // (the file redirect doesn't cover it).
        ConfigStore.RegKeyPath = @"Software\CryptoKeyTests";
        Microsoft.Win32.Registry.CurrentUser.DeleteSubKeyTree(
            ConfigStore.RegKeyPath, throwOnMissingSubKey: false);
    }
}
