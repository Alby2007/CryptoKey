using Xunit;

namespace CryptoKey.Ui.Tests;

/// <summary>
/// Vault page presenter — the missing-driver and user-seal cases behind the
/// "create reported success with no Dokany / Close vault did nothing" bug.
/// </summary>
public class VaultPresenterTests
{
    private static VaultFacts Facts(
        VaultState state = VaultState.NoImage,
        bool enabled = true,
        bool imageExists = false,
        bool driverPresent = true,
        string? driverHint = "Install Dokany from dokan-dev.github.io",
        bool keyVerified = true) =>
        new(state, enabled, imageExists, "img.ckv", driverPresent, driverHint,
            keyVerified, null, "V:", "V:", false, false, true, false, true, 0, 256);

    [Fact]
    public void Missing_driver_warns_before_an_image_exists()
    {
        // First-timer, no vault yet — the banner must appear BEFORE create,
        // not only after the dead-end image is already on disk.
        VaultView v = VaultPresenter.Present(
            Facts(VaultState.NoImage, imageExists: false, driverPresent: false));
        Assert.NotNull(v.DriverNote);
        Assert.Equal("Install Dokany from dokan-dev.github.io", v.DriverNote);
        Assert.True(v.CreateEnabled); // click still runs — it fails at engine time
    }

    [Fact]
    public void Missing_driver_hint_falls_back()
    {
        VaultView v = VaultPresenter.Present(
            Facts(driverPresent: false, driverHint: null));
        Assert.Equal("Dokany driver missing", v.DriverNote);
    }

    [Fact]
    public void Sealed_with_key_held_offers_unseal_not_close()
    {
        // After Close vault the page must land on Sealed — with a way back
        // (Unseal) and no pointless still-enabled Close.
        VaultView v = VaultPresenter.Present(
            Facts(VaultState.Sealed, imageExists: true, keyVerified: true));
        Assert.True(v.MountVisible);
        Assert.True(v.MountEnabled);
        Assert.Equal("Unseal", v.MountText);
        Assert.False(v.CloseEnabled);
        Assert.False(v.OpenEnabled);
    }

    [Fact]
    public void Sealed_without_key_hides_unseal()
    {
        VaultView v = VaultPresenter.Present(
            Facts(VaultState.Sealed, imageExists: true, keyVerified: false));
        Assert.False(v.MountVisible);
        Assert.False(v.MountEnabled);
        Assert.False(v.CloseEnabled);
    }

    [Fact]
    public void Needs_driver_state_can_close()
    {
        // The stuck-state the user hit — Close must be live here.
        VaultView v = VaultPresenter.Present(
            Facts(VaultState.NeedsDriver, imageExists: true, driverPresent: false));
        Assert.True(v.CloseEnabled);
        Assert.True(v.MountEnabled); // Mount retries — fails honestly, hints the driver
        Assert.Equal("Mount", v.MountText);
    }

    [Fact]
    public void Mounted_can_close_and_open()
    {
        VaultView v = VaultPresenter.Present(
            Facts(VaultState.Mounted, imageExists: true));
        Assert.True(v.CloseEnabled);
        Assert.True(v.OpenEnabled);
        Assert.Equal("Dismount", v.MountText);
    }

    [Fact]
    public void Unsealed_can_close()
    {
        VaultView v = VaultPresenter.Present(
            Facts(VaultState.Unsealed, imageExists: true));
        Assert.True(v.CloseEnabled);
    }

    [Fact]
    public void Rolled_back_cannot_be_closed()
    {
        // Close must not hide a pending rollback decision — Accept is the action.
        VaultView v = VaultPresenter.Present(
            Facts(VaultState.RolledBack, imageExists: true));
        Assert.False(v.CloseEnabled);
        Assert.True(v.MountIsAcceptRollback);
    }
}
