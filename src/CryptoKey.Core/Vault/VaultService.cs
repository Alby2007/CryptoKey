using System.Security.Cryptography;

namespace CryptoKey;

internal enum VaultState
{
    /// <summary>Guard.VaultEnabled off — no vault work at all.</summary>
    Disabled,
    /// <summary>Enabled but no image exists at the configured path.</summary>
    NoImage,
    /// <summary>Image exists; no verified device secret in memory (key absent).</summary>
    Sealed,
    /// <summary>The verified secret unwrapped no key slot — the vault fell out of
    /// the two-generation window. Permanent; reformat is the only path.</summary>
    SealedDead,
    /// <summary>Secret verified but the mount engine's driver is absent.</summary>
    NeedsDriver,
    /// <summary>Volume key held in memory; not mounted (auto-mount off or just dismounted).</summary>
    Unsealed,
    /// <summary>Mounted at a drive letter.</summary>
    Mounted,
}

/// <summary>
/// Orchestrates the encrypted vault lifecycle: consumes verified device
/// secrets from the guard, unwraps/mounts on verification, force-dismounts
/// on key removal or lock, and slides the two key slots forward on secret
/// rotation.
///
/// Secret hygiene: device secrets and the KEK-window live in
/// <see cref="PinnedBuffer"/>s — GC can't move them, and every teardown
/// path zeroes them. Nothing here is ever logged or serialized.
/// </summary>
internal sealed class VaultService : IDisposable
{
    private readonly KeyConfig _config;
    private readonly IVaultMounter _mounter;
    private readonly Action<string> _log;

    private PinnedBuffer? _secret;     // newest verified device secret
    private PinnedBuffer? _prevSecret; // the distinct secret before it (slot-B coverage)
    private uint _secretGen;
    private uint _prevSecretGen;
    private VaultVolume? _vol;         // open image — volKey lives inside
    private IVaultMount? _mount;
    private VaultState _state = VaultState.Disabled;

    /// <summary>Raised (on the caller's thread) whenever <see cref="State"/> changes.</summary>
    public event Action? StatusChanged;

    public VaultService(KeyConfig config, IVaultMounter mounter, Action<string> log)
    {
        _config = config;
        _mounter = mounter;
        _log = log;
        _state = InitialState();
    }

    // ------------------------------------------------------------------ state

    public VaultState State => _state;

    public string ImagePath =>
        !string.IsNullOrWhiteSpace(_config.Guard.VaultImagePath)
            ? _config.Guard.VaultImagePath
            : DefaultImagePath;

    /// <summary>Default image home — the installed app's own directory.</summary>
    public static string DefaultImagePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "CryptoKey", "vault.ckv");

    /// <summary>"V:\" style — the Dokan mount point.</summary>
    public string MountPoint => _mount?.MountPoint ?? ConfiguredMountPoint;

    public string ConfiguredMountPoint
    {
        get
        {
            string p = _config.Guard.VaultMountPoint.Trim();
            if (p.Length >= 1 && char.IsLetter(p[0]))
                return char.ToUpperInvariant(p[0]) + ":";
            return "V:";
        }
    }

    public bool ImageExists => File.Exists(ImagePath);

    public bool DriverPresent => _mounter.DriverPresent;

    public string? DriverHint => _mounter.DriverHint;

    /// <summary>The key is verified and its secret is in memory (kept for re-wraps).</summary>
    public bool SecretHeld => _secret != null;

    /// <summary>Live usage; null while sealed/dismounted.</summary>
    public (long Used, long Total)? Usage => _vol?.GetUsage();

    /// <summary>Slot generations, when an image is readable.</summary>
    public (uint A, uint B)? SlotGens => _vol?.SlotGens;

    private VaultState InitialState()
    {
        if (!_config.Guard.VaultEnabled)
            return VaultState.Disabled;
        return ImageExists ? VaultState.Sealed : VaultState.NoImage;
    }

    private void SetState(VaultState next)
    {
        if (_state == next)
            return;
        _state = next;
        StatusChanged?.Invoke();
    }

    // --------------------------------------------------------- guard call-ins

    /// <summary>
    /// The key verified: take ownership of <paramref name="secret"/>
    /// (it is copied to a pinned buffer and the caller's copy is zeroed).
    /// Unseals the image and auto-mounts when enabled; on a new generation
    /// the key slots slide forward to keep the current/previous window.
    /// </summary>
    public void KeyVerified(byte[] secret, uint gen)
    {
        if (!_config.Guard.VaultEnabled)
        {
            CryptographicOperations.ZeroMemory(secret);
            return;
        }
        lock (this)
        {
            if (_secretGen == gen && _secret != null)
            {
                // Same secret re-verifying — don't auto-mount: a manual
                // Close-vault must hold for the rest of the key session.
                CryptographicOperations.ZeroMemory(secret);
                return;
            }

            var held = new PinnedBuffer(secret);
            CryptographicOperations.ZeroMemory(secret);

            if (_vol == null && !ImageExists)
            {
                SetState(VaultState.NoImage);
            }
            else if (_vol == null && ImageExists)
            {
                // Sealed image — try to unwrap under the just-verified secret.
                VaultHeader? peek = VaultVolume.PeekHeader(ImagePath);
                if (peek == null)
                {
                    SetState(VaultState.SealedDead);
                    held.Dispose();
                    return;
                }
                byte[] kek = VaultFormat.DeriveKek(held.Bytes, peek.Salt);
                try
                {
                    if (!VaultVolume.TryOpen(ImagePath, kek,
                            out VaultVolume? vol, out _, out int slot))
                    {
                        // No slot unwrapped OR the manifest is dead — either
                        // way the page reports terminal-sealed.
                        SetState(VaultState.SealedDead);
                        held.Dispose();
                        return;
                    }
                    _vol = vol;
                    _log($"Vault unsealed (key slot {slot}, wrapped at gen {PeekSlotGen(vol!, slot)}).");
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(kek);
                }
            }
            else if (_vol != null)
            {
                // New generation — slide the slot window forward so the vault
                // stays openable under current + previous secrets.
                try
                {
                    _vol.ReWrapKeys(
                        VaultFormat.DeriveKek(held.Bytes, _vol.Salt),
                        _secret != null
                            ? VaultFormat.DeriveKek(_secret.Bytes, _vol.Salt)
                            : null,
                        gen, _secretGen);
                }
                catch (Exception ex)
                {
                    _log($"Vault key-slot re-wrap failed ({ex.Message}) — retries next verify.");
                }
            }

            _prevSecret?.Dispose();
            _prevSecret = _secret;
            _prevSecretGen = _secretGen;
            _secret = held;
            _secretGen = gen;
            TryAutoMount();
        }
    }

    private static uint PeekSlotGen(VaultVolume vol, int slot)
    {
        (uint a, uint b) = vol.SlotGens;
        return slot == 0 ? a : b;
    }

    /// <summary>
    /// Key gone (removed, unverified, locked, shutdown): force-dismount and
    /// zero every held secret. Idempotent — safe on any teardown path.
    /// </summary>
    public void KeyGone()
    {
        lock (this)
        {
            bool wasMounted = _mount != null;
            DismountLocked();
            CloseVolumeLocked();
            _secret?.Dispose();
            _prevSecret?.Dispose();
            _secret = null;
            _prevSecret = null;
            _secretGen = _prevSecretGen = 0;
            if (_state == VaultState.Disabled)
                return;
            SetState(ImageExists ? VaultState.Sealed : VaultState.NoImage);
            if (wasMounted)
                _log("Vault dismounted — key gone.");
        }
    }

    // ------------------------------------------------------------- operations

    /// <summary>Create the image under the held secret (requires a verified key).</summary>
    public bool TryCreate(int sizeMb, out string error)
    {
        lock (this)
        {
            error = "";
            if (_secret == null)
            {
                error = "insert your key to create";
                return false;
            }
            if (ImageExists)
            {
                error = "vault image already exists";
                return false;
            }
            try
            {
                _vol = VaultVolume.Create(ImagePath, sizeMb, _secret.Bytes, _secretGen);
                _log($"Vault image created ({sizeMb} MB) — wrapped at gen {_secretGen}.");
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
            TryAutoMount();
            SetState(_state is VaultState.Mounted or VaultState.NeedsDriver
                ? _state : VaultState.Unsealed);
            return true;
        }
    }

    /// <summary>Reformat: destroy the image and recreate under the held secret.</summary>
    public bool TryReformat(int sizeMb, out string error)
    {
        lock (this)
        {
            error = "";
            if (_secret == null)
            {
                error = "insert your key to reformat";
                return false;
            }
            DismountLocked();
            CloseVolumeLocked();
            try
            {
                if (File.Exists(ImagePath))
                    File.Delete(ImagePath);
                _vol = VaultVolume.Create(ImagePath, sizeMb, _secret.Bytes, _secretGen);
                _log($"Vault reformatted ({sizeMb} MB) — all previous contents destroyed.");
            }
            catch (Exception ex)
            {
                error = ex.Message;
                SetState(ImageExists ? VaultState.Sealed : VaultState.NoImage);
                return false;
            }
            TryAutoMount();
            SetState(_state is VaultState.Mounted or VaultState.NeedsDriver
                ? _state : VaultState.Unsealed);
            return true;
        }
    }

    /// <summary>Delete the image file entirely (after dismounting if mounted).</summary>
    public bool TryDeleteImage(out string error)
    {
        lock (this)
        {
            error = "";
            DismountLocked();
            CloseVolumeLocked();
            try
            {
                if (File.Exists(ImagePath))
                    File.Delete(ImagePath);
                _log("Vault image deleted.");
                SetState(VaultState.NoImage);
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }
    }

    /// <summary>Mount the unsealed volume. Honest failure when the driver is absent.</summary>
    public bool TryMount(out string error)
    {
        lock (this)
        {
            error = "";
            if (_vol == null)
            {
                error = "vault is sealed — insert the key";
                return false;
            }
            if (_mount != null)
                return true;
            if (!_mounter.DriverPresent)
            {
                error = _mounter.DriverHint ?? "mount driver unavailable";
                SetState(VaultState.NeedsDriver);
                return false;
            }
            _mount = _mounter.Mount(_vol, ConfiguredMountPoint, out string? mErr);
            if (_mount == null)
            {
                error = mErr ?? "mount failed";
                return false;
            }
            _mount.Detached += OnMountDetached;
            SetState(VaultState.Mounted);
            _log($"Vault mounted at {_mount.MountPoint}");
            return true;
        }
    }

    /// <summary>Dismount but stay unsealed (volKey kept — instant remount).</summary>
    public bool TryUnmount(out string error)
    {
        lock (this)
        {
            error = "";
            if (_mount == null)
                return true;
            DismountLocked();
            SetState(VaultState.Unsealed);
            _log("Vault dismounted.");
            return true;
        }
    }

    /// <summary>Repoint the mount letter for the next mount.</summary>
    public void ApplyMountPoint(string letter)
        => _config.Guard.VaultMountPoint = letter;

    // ----------------------------------------------------------------- intern

    private void TryAutoMount()
    {
        if (_vol == null || _mount != null)
            return;
        if (!_mounter.DriverPresent)
        {
            SetState(VaultState.NeedsDriver);
            return;
        }
        if (!_config.Guard.VaultAutoMount)
        {
            SetState(VaultState.Unsealed);
            return;
        }
        if (TryMount(out string err))
            return;
        _log($"Vault auto-mount failed: {err}");
        SetState(VaultState.Unsealed);
    }

    /// <summary>Force-dismount — the mount thread and open handles unwind via the driver.</summary>
    private void DismountLocked()
    {
        if (_mount == null)
            return;
        IVaultMount m = _mount;
        _mount = null;
        m.Detached -= OnMountDetached;
        try { m.Dispose(); }
        catch (Exception) { }
    }

    private void CloseVolumeLocked()
    {
        if (_vol == null)
            return;
        try { _vol.Dispose(); } // flushes the manifest on the way out
        catch (Exception) { }
        _vol = null;
    }

    private void OnMountDetached()
    {
        // The FS detached on its own (external unmount) — on a pool thread.
        lock (this)
        {
            _mount = null;
            if (_state == VaultState.Mounted)
            {
                SetState(VaultState.Unsealed);
                _log("Vault mount detached.");
            }
        }
    }

    /// <summary>Refresh state for config changes (enable/disable, path change).</summary>
    public void ReloadConfig()
    {
        lock (this)
        {
            if (!_config.Guard.VaultEnabled)
            {
                // Turning the vault off seals it the same as pulling the key.
                KeyGone();
                SetState(VaultState.Disabled);
                return;
            }
            if (_state == VaultState.Disabled)
                SetState(InitialState());
            else if (_vol == null)
                SetState(ImageExists ? VaultState.Sealed : VaultState.NoImage);
            else if (_mount == null)
                SetState(VaultState.Unsealed);
        }
    }

    public void Dispose() => KeyGone();
}
