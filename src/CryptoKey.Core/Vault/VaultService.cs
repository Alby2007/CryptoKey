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
    /// <summary>Image present but unreadable (bad format, dead manifests, or an
    /// I/O error mid-open). May be transient — the next verify retries.</summary>
    Corrupt,
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
    private uint _secretGen;
    private VaultVolume? _vol;         // open image — volKey lives inside
    private IVaultMount? _mount;
    private VaultState _state = VaultState.Disabled;
    private int _opSeq;                // bumped on every lifecycle event; stale async commits drop
    private int _unmountSeq;           // bumped on TryUnmount — a mount issued before it drops
    private Task? _pendingOps;         // in-flight unseal/auto-mount chain (for CLI/test waits)
    private long _lastOpenAttempt;     // TickCount64 — paces the transient-failure retry

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
        PinnedBuffer? held = null;
        lock (this)
        {
            bool retryOpen = false;
            if (_secretGen == gen && _secret != null)
            {
                // Same secret re-verifying — normally a no-op (a manual
                // Close-vault must hold for the rest of the session).
                // Exception: a Sealed/Corrupt state may be a transient read
                // failure — retry throttled so a real dead-seal isn't
                // re-read every poll.
                retryOpen = _vol == null && ImageExists
                    && _state is VaultState.Sealed or VaultState.Corrupt
                    && (_pendingOps?.IsCompleted ?? true)
                    && Environment.TickCount64 - _lastOpenAttempt > 5000;
                if (!retryOpen)
                {
                    CryptographicOperations.ZeroMemory(secret);
                    return;
                }
            }

            held = retryOpen ? _secret! : new PinnedBuffer(secret);
            CryptographicOperations.ZeroMemory(secret);
            // The previous secret stays alive until the rewrap below derives
            // its KEK — disposing it here would collapse the heal window.
            PinnedBuffer? prevHeld = _secret;
            uint prevGen = _secretGen;
            int seq;
            if (retryOpen)
            {
                seq = _opSeq;
            }
            else
            {
                seq = ++_opSeq;
                _secret = held;
                _secretGen = gen;
            }

            if (_vol == null && !ImageExists)
            {
                SetState(VaultState.NoImage);
            }
            else if (_vol == null && ImageExists)
            {
                // Sealed image — unwrap under the verified secret. The heavy
                // part (two 4 MiB manifest slots + JSON) runs off the
                // caller's thread so the guard's UI pump doesn't stall.
                VaultHeader? peek = VaultVolume.PeekHeader(ImagePath,
                    out VaultOpenError peekErr);
                if (peek == null)
                {
                    // NoImage = transient/missing → stay Sealed, paced retry.
                    // BadFormat = both pages rejected (e.g. a v1 image or
                    // genuine header corruption) — Corrupt, which retries too.
                    SetState(peekErr == VaultOpenError.NoImage
                        ? (ImageExists ? VaultState.Sealed : VaultState.NoImage)
                        : VaultState.Corrupt);
                    if (!retryOpen)
                        prevHeld?.Dispose(); // held swapped in — old secret dies here
                    return;
                }
                _lastOpenAttempt = Environment.TickCount64;
                byte[] kek = VaultFormat.DeriveKek(held.Bytes, peek.Salt);
                _pendingOps = Task.Run(() => OpenThenMount(kek, seq));
            }
            else if (_vol != null && !retryOpen)
            {
                // New generation — slide the slot window forward so the vault
                // stays openable under current + previous secrets. KEKs are
                // scoped arrays — zero them once the wrap lands. Note the
                // PREVIOUS secret prevHeld feeds slot B, not the new one.
                byte[] kekCur = VaultFormat.DeriveKek(held.Bytes, _vol.Salt);
                byte[]? kekPrev = prevHeld != null
                    ? VaultFormat.DeriveKek(prevHeld.Bytes, _vol.Salt)
                    : null;
                try
                {
                    _vol.ReWrapKeys(kekCur, kekPrev, gen, prevGen);
                }
                catch (Exception ex)
                {
                    _log($"Vault key-slot re-wrap failed ({ex.Message}) — retries next verify.");
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(kekCur);
                    if (kekPrev != null)
                        CryptographicOperations.ZeroMemory(kekPrev);
                }
            }

            if (!retryOpen)
                prevHeld?.Dispose(); // old generation's secret — fully replaced
            if (_vol != null)
                KickAutoMount(seq); // heal-mount after a rewrap edge
        }
    }

    /// <summary>
    /// Pool-thread unseal: TryOpen is the heavy read; adoption happens under
    /// the lock only if this secret is still the live one (a KeyGone or
    /// newer verify bumps <see cref="_opSeq"/> and drops the result).
    /// </summary>
    private void OpenThenMount(byte[] kek, int seq)
    {
        VaultVolume? vol = null;
        VaultOpenError err = VaultOpenError.None;
        int slot = -1;
        try
        {
            VaultVolume.TryOpen(ImagePath, kek, out vol, out err, out slot);
        }
        catch (Exception ex)
        {
            vol = null;
            err = VaultOpenError.Corrupt;
            _log($"Vault open error: {ex.Message}");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }

        bool adopted = false;
        bool autoMount = false;
        int useq = 0;
        lock (this)
        {
            bool alive = seq == _opSeq && _vol == null;
            if (vol != null && alive)
            {
                _vol = vol;
                adopted = true;
                _log($"Vault unsealed (key slot {slot}, wrapped at gen {PeekSlotGen(vol, slot)}).");
                if (!_mounter.DriverPresent)
                    SetState(VaultState.NeedsDriver);
                else if (!_config.Guard.VaultAutoMount)
                    SetState(VaultState.Unsealed);
                else
                {
                    SetState(VaultState.Unsealed); // honest transitional state
                    autoMount = true;
                    useq = _unmountSeq; // fence for the mount commit below
                }
            }
            else
            {
                vol?.Dispose();
                if (seq == _opSeq)
                    SetState(err switch
                    {
                        VaultOpenError.NoImage => VaultState.NoImage,
                        VaultOpenError.Sealed => VaultState.SealedDead,
                        _ => VaultState.Corrupt, // BadFormat/IO — maybe transient
                    });
            }
        }
        // Same pool task runs the mount — _pendingOps covers the whole chain.
        if (adopted && autoMount)
            MountBody(vol!, seq, useq);
    }

    /// <summary>
    /// The auto-mount's slow half — runs on a pool thread; the commit
    /// re-validates under the lock so a racing teardown drops the mount.
    /// <paramref name="useq"/> fences out a TryUnmount that landed while the
    /// driver call was in-flight.
    /// </summary>
    private void MountBody(VaultVolume vol, int seq, int useq)
    {
        IVaultMount? m;
        string? err;
        try
        {
            m = _mounter.Mount(vol, ConfiguredMountPoint, out err);
        }
        catch (Exception ex)
        {
            m = null;
            err = ex.Message;
        }
        lock (this)
        {
            if (seq != _opSeq || useq != _unmountSeq
                || !ReferenceEquals(_vol, vol) || _mount != null)
            {
                m?.Dispose(); // KeyGone/reformat/unmount raced the mount — drop it
                return;
            }
            if (m == null)
            {
                _log($"Vault auto-mount failed: {err}");
                SetState(VaultState.Unsealed);
                return;
            }
            _mount = m;
            m.Detached += OnMountDetached;
            SetState(VaultState.Mounted);
            _log($"Vault mounted at {m.MountPoint}");
        }
    }

    /// <summary>
    /// Auto-mount off the caller's thread — the driver's mount call can take
    /// ~1s and must not stall the pump or hold the service lock (a KeyGone
    /// waiting on it would delay teardown). The commit re-validates under
    /// the lock; a racing teardown drops the mount.
    /// </summary>
    private void KickAutoMount(int seq)
    {
        lock (this)
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
            SetState(VaultState.Unsealed); // transitional — the task flips it to Mounted
            VaultVolume vol = _vol;
            int useq = _unmountSeq;
            _pendingOps = Task.Run(() => MountBody(vol, seq, useq));
        }
    }

    /// <summary>
    /// Block until the in-flight unseal/mount chain settles (or times out) —
    /// standalone CLI and tests call this after KeyVerified.
    /// </summary>
    public bool WaitForPendingOps(int timeoutMs = 15000)
    {
        long deadline = Environment.TickCount64 + timeoutMs;
        while (true)
        {
            Task? pending;
            lock (this)
                pending = _pendingOps;
            if (pending == null)
                return true;
            if (pending.IsCompleted)
            {
                lock (this)
                {
                    if (ReferenceEquals(_pendingOps, pending))
                    {
                        _pendingOps = null;
                        return true;
                    }
                }
                continue; // a successor task published itself — wait on that
            }
            long left = deadline - Environment.TickCount64;
            if (left <= 0)
                return false;
            try
            {
                pending.Wait((int)Math.Min(left, int.MaxValue));
            }
            catch (Exception)
            {
                // A faulted op is still a settled op — treat as done.
            }
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
            ++_opSeq; // drop any in-flight unseal/mount — its commit bounces off
            bool wasMounted = _mount != null;
            DismountLocked();
            CloseVolumeLocked();
            _secret?.Dispose();
            _secret = null;
            _secretGen = 0;
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
            ++_opSeq; // any pending open against a prior image is stale now
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
            KickAutoMount(_opSeq);
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
            ++_opSeq;
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
            KickAutoMount(_opSeq);
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
            ++_opSeq;
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
            _unmountSeq++; // fence: an in-flight auto-mount must not land now
            if (_mount == null)
                return true; // Unsealed/NeedsDriver already; a pending MountBody will drop
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
