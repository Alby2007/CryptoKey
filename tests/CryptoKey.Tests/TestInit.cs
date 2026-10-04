using System.Runtime.CompilerServices;

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
    }
}
