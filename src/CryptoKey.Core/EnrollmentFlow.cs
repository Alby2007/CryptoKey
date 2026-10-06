using System.Security.Cryptography;

namespace CryptoKey;

internal enum ConfirmResult
{
    Match,
    Mismatch,
    Exhausted,
}

internal sealed record EnrollResult(bool Ok, string Message, KeyConfig? Config,
    string? KeyPath, IReadOnlyList<string> Warnings);

/// <summary>
/// Enrollment as a console-free state machine: pick a drive → a phrase is
/// generated (shown once) → retype to confirm (3 tries, normalized) →
/// commit (config first, then the attested keyfile; rollback on failure).
/// The CLI <see cref="Enrollment"/> and the GUI onboarding wizard both drive
/// this, so the security-relevant ordering lives in exactly one place.
/// </summary>
internal sealed class EnrollmentFlow
{
    public const int SecretBytes = 64;
    public const int MaxConfirmAttempts = 3;

    private string? _phrase;
    private bool _confirmed;

    /// <summary>The currently enrolled config, if any (re-enroll keeps its guard prefs).</summary>
    public KeyConfig? Existing { get; }

    public UsbDisk? Disk { get; private set; }
    public string? Volume { get; private set; }

    /// <summary>Non-fatal caveat for the chosen drive (blank serial).</summary>
    public string? DiskWarning { get; private set; }

    /// <summary>The generated recovery phrase — shown once, never persisted in clear.</summary>
    public string? Phrase => _phrase;

    public int ConfirmAttempts { get; private set; }
    public bool Confirmed => _confirmed;

    public EnrollmentFlow()
    {
        try { Existing = ConfigStore.Load(); }
        catch (Exception) { Existing = null; }
    }

    /// <summary>USB disks eligible for enrollment; throws on enumeration failure.</summary>
    public static List<UsbDisk> ListDisks() => Platform.Services.Usb.Enumerate();

    /// <summary>
    /// Choose the drive. Returns an error for a drive with no mounted volume
    /// (the keyfile needs somewhere to live); otherwise generates a fresh
    /// phrase and resets confirmation.
    /// </summary>
    public string? SelectDisk(UsbDisk disk)
    {
        string? volume = disk.VolumePaths.FirstOrDefault();
        if (volume == null)
            return "Selected drive has no mounted volume.";
        Disk = disk;
        Volume = volume;
        DiskWarning = string.IsNullOrEmpty(disk.SerialNumber)
            ? "This drive reports a blank serial number — matching may be unreliable."
            : null;
        _phrase = RecoveryPhrase.Generate();
        _confirmed = false;
        ConfirmAttempts = 0;
        return null;
    }

    /// <summary>
    /// Retype-to-confirm. Normalization forgives case, separators, and
    /// ambiguous glyphs (O/0, I/L/1) — the same rules unlock uses.
    /// </summary>
    public ConfirmResult Confirm(ReadOnlySpan<char> typed)
    {
        if (_phrase == null)
            throw new InvalidOperationException("Select a disk before confirming.");
        if (_confirmed)
            return ConfirmResult.Match;
        if (ConfirmAttempts >= MaxConfirmAttempts)
            return ConfirmResult.Exhausted;

        Span<char> want = stackalloc char[64];
        Span<char> got = stackalloc char[64];
        try
        {
            int wantLen = RecoveryPhrase.Normalize(_phrase.AsSpan(), want);
            int gotLen = RecoveryPhrase.Normalize(typed, got);
            ConfirmAttempts++;
            if (gotLen == wantLen && got[..gotLen].SequenceEqual(want[..wantLen]))
            {
                _confirmed = true;
                return ConfirmResult.Match;
            }
            return ConfirmAttempts >= MaxConfirmAttempts
                ? ConfirmResult.Exhausted
                : ConfirmResult.Mismatch;
        }
        finally
        {
            want.Clear();
            got.Clear();
        }
    }

    /// <summary>
    /// Write it for real. Config is created first (the v2 keyfile's
    /// attestation MAC covers the serial, phrase hash, and covered guard
    /// fields — so <paramref name="configure"/> runs BEFORE the keyfile is
    /// wrapped). A config-save failure deletes the keyfile so nothing on the
    /// drive verifies against nothing.
    /// </summary>
    public EnrollResult Commit(Action<GuardSettings>? configure = null)
    {
        var warnings = new List<string>();
        if (Disk == null || Volume == null || _phrase == null)
            return new(false, "No drive selected.", null, null, warnings);
        if (!_confirmed)
            return new(false, "The recovery phrase hasn't been confirmed.", null, null, warnings);

        byte[] secret = RandomNumberGenerator.GetBytes(SecretBytes);
        try
        {
            KeyConfig fresh = ConfigStore.CreateNew(Disk.SerialNumber, secret, _phrase);
            if (Existing?.Guard != null)
                fresh.Guard = Existing.Guard;
            configure?.Invoke(fresh.Guard);

            string keyPath = KeyVerifier.KeyFilePath(Volume);
            try
            {
                // AtomicFile flushes to media before the rename — no truncated
                // keyfile if the drive is pulled mid-write.
                AtomicFile.WriteAllBytes(keyPath, KeyVerifier.WrapKeyfile(secret, fresh));
                Platform.Services.KeyfileAttrs.Hide(keyPath);
            }
            catch (Exception ex)
            {
                return new(false, $"Failed to write keyfile to {keyPath}: {ex.Message}",
                    null, null, warnings);
            }

            try
            {
                ConfigStore.Save(fresh);
            }
            catch (Exception ex)
            {
                try { File.Delete(keyPath); } catch { }
                return new(false, $"Failed to save config to {ConfigStore.ConfigPath}: {ex.Message}",
                    null, null, warnings);
            }

            // Best-effort host extras (shell shortcuts) — never fail enrollment.
            try
            {
                Platform.Services.EnrollmentExtras.AfterEnroll();
            }
            catch (Exception ex)
            {
                warnings.Add($"Post-enroll extras skipped: {ex.Message}");
            }

            _phrase = null; // the phrase's job is done — drop the reference
            return new(true, $"Enrolled {Disk.Model} on {Volume}.", fresh, keyPath, warnings);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }
}
