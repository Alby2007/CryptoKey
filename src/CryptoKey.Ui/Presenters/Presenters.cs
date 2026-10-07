namespace CryptoKey.Ui;

/// <summary>Semantic color role — views map it to a token brush.</summary>
internal enum Tone
{
    Neutral,
    Ok,
    Warn,
    Danger,
    Signal,
}

/// <summary>What the signature key artwork shows.</summary>
internal enum KeyVisualState
{
    /// <summary>Seated, LED green, slow breathing glow.</summary>
    Armed,
    /// <summary>Seated, cyan scan sweeps the blade (2FA: key ok, phrase pending).</summary>
    Verifying,
    /// <summary>Ejected, port ring + LED red.</summary>
    Locked,
    /// <summary>Seated but dimmed, amber LED, countdown arc.</summary>
    Paused,
    /// <summary>Ejected and dim — no key, nothing armed (manual-lock mode).</summary>
    Absent,
    /// <summary>Seated, red glitch-jitter — unverified or clone-suspect key.</summary>
    Tamper,
}

internal sealed record Chip(string Text, Tone Tone);

internal sealed record HomeView(
    GuardState State,
    string StateWord,
    string Reason,
    Tone Accent,
    KeyVisualState Visual,
    IReadOnlyList<Chip> Chips,
    string KeyTitle,
    string KeySerial,
    string KeyDetail,
    bool CanLock,
    bool CanPause,
    bool CanResume);

/// <summary>Home hero + key card — ported 1:1 from the legacy dashboard's ApplySnapshot.</summary>
internal static class HomePresenter
{
    public static HomeView Present(StatusSnapshot s, SettingsView settings, bool devMode, bool elevated)
    {
        string word, reason;
        Tone accent;
        if (!s.Enrolled && s.State != GuardState.Locked)
        {
            // Dormant — a config exists but no key is bound. Distinct from
            // "key absent": there's nothing enrolled to BE absent.
            word = "NO KEY";
            accent = Tone.Neutral;
            reason = "No key enrolled — auto-lock is off.";
        }
        else switch (s.State)
        {
            case GuardState.Locked:
                word = "LOCKED";
                accent = Tone.Danger;
                // Armed-while-locked only happens under 2FA — the key factor
                // is satisfied and the recovery phrase completes the unlock.
                reason = s.KeyFactorArmed
                    ? "Key verified — enter the recovery phrase to finish unlocking."
                    : !s.Enrolled
                        ? "Locked — the recovery phrase still unlocks."
                        : s.LastVerifyFailure ?? "Your key is out. Insert it to unlock.";
                break;
            case GuardState.Paused:
                word = "PAUSED";
                accent = Tone.Warn;
                reason = $"Auto-lock resumes at {s.PausedUntil:HH:mm}.";
                break;
            default:
                word = "ARMED";
                accent = Tone.Ok;
                reason = s.KeyPresent
                    ? "Pull the key and this machine locks instantly."
                    : "Waiting for your key.";
                break;
        }

        var chips = new List<Chip>();
        if (!s.Enrolled)
            chips.Add(new Chip("no key enrolled", Tone.Neutral));
        else if (s.KeyPresent)
            chips.Add(s.LastVerifyFailure != null
                ? new Chip("key unverified", Tone.Danger)
                : new Chip("key verified", Tone.Ok));
        else
            chips.Add(new Chip("key absent", Tone.Neutral));
        if (s.TamperNote != null)
            chips.Add(new Chip("possible clone", Tone.Danger));
        if (devMode)
            chips.Add(new Chip("dev mode", Tone.Warn));
        if (s.WatchdogAlive)
            chips.Add(new Chip("watchdog", Tone.Signal));
        if (elevated)
            chips.Add(new Chip("elevated", Tone.Signal));
        if (s.Vault is VaultStatus vs)
            chips.Add(VaultChip(vs));
        if (s.PendingUpdate != null)
            chips.Add(new Chip($"update {s.PendingUpdate}", Tone.Signal));

        string title, serial, detail;
        serial = $"serial {settings.DeviceSerial}";
        if (!s.Enrolled)
        {
            title = "No key enrolled";
            serial = "";
            detail = "The recovery phrase, account, and settings are kept — " +
                "set up a key to re-arm.";
        }
        else if (s.KeyPresent)
        {
            title = s.Model ?? "USB drive";
            detail = s.LastVerifyFailure ?? $"Keyfile verified — generation {settings.RotationCount}";
        }
        else
        {
            title = "Key not detected";
            detail = "Insert the enrolled drive.";
        }

        return new HomeView(s.State, word, reason, accent, VisualFor(s), chips,
            title, serial, detail,
            CanLock: s.State != GuardState.Locked,
            // Pausing means nothing with no auto-lock armed.
            CanPause: s.State != GuardState.Locked && s.Enrolled,
            CanResume: s.State == GuardState.Paused);
    }

    public static KeyVisualState VisualFor(StatusSnapshot s) => s.State switch
    {
        GuardState.Locked => s.KeyFactorArmed ? KeyVisualState.Verifying : KeyVisualState.Locked,
        GuardState.Paused => KeyVisualState.Paused,
        _ when !s.KeyPresent => KeyVisualState.Absent,
        _ when s.LastVerifyFailure != null || s.TamperNote != null => KeyVisualState.Tamper,
        _ => KeyVisualState.Armed,
    };

    public static Chip VaultChip(VaultStatus vs) => vs.State switch
    {
        VaultState.Mounted => new Chip($"vault {vs.MountPoint}", Tone.Ok),
        VaultState.Unsealed => new Chip("vault unsealed", Tone.Warn),
        VaultState.NeedsDriver => new Chip("vault needs driver", Tone.Warn),
        VaultState.SealedDead => new Chip("vault dead", Tone.Danger),
        VaultState.RolledBack => new Chip("vault rolled back", Tone.Danger),
        VaultState.Corrupt => new Chip("vault corrupt", Tone.Danger),
        VaultState.TpmLocked => new Chip("vault TPM-locked", Tone.Danger),
        _ => new Chip("vault sealed", Tone.Neutral),
    };

    /// <summary>Fraction of the pause elapsed (0..1) for the countdown arc.</summary>
    public static double PauseProgress(DateTime? until, DateTime now, TimeSpan total)
    {
        if (until is not DateTime u || total <= TimeSpan.Zero)
            return 0;
        double left = (u - now).TotalSeconds / total.TotalSeconds;
        return Math.Clamp(1 - left, 0, 1);
    }
}

/// <summary>Everything the Vault page reads, gathered in one engine-thread hop.</summary>
internal sealed record VaultFacts(
    VaultState State,
    bool Enabled,
    bool ImageExists,
    string ImagePath,
    bool DriverPresent,
    string? DriverHint,
    bool KeyVerified,
    (long Used, long Total)? Usage,
    string MountPoint,
    string ConfiguredMountPoint,
    bool TpmBound,
    bool HasRecovery,
    bool TpmAvailable,
    bool NeedsRebind,
    bool AutoMount,
    int IdleMinutes,
    int SizeMb)
{
    public static VaultFacts Gather(GuardService svc, KeyConfig cfg)
    {
        VaultService v = svc.Vault;
        StatusSnapshot snap = svc.Snapshot();
        return new VaultFacts(v.State, cfg.Guard.VaultEnabled, v.ImageExists, v.ImagePath,
            v.DriverPresent, v.DriverHint, snap.KeyFactorArmed || v.SecretHeld, v.Usage,
            v.MountPoint, v.ConfiguredMountPoint, v.ImageTpmBound, v.ImageHasRecovery,
            v.TpmAvailable, v.NeedsRebind, cfg.Guard.VaultAutoMount,
            cfg.Guard.VaultIdleMinutes, cfg.Guard.VaultSizeMb);
    }
}

/// <summary>Which action the machine-binding primary button performs.</summary>
internal enum TpmAction
{
    Bind,
    UnlockWithPhrase,
    Rebind,
    None,
}

internal sealed record VaultView(
    string Badge,
    Tone Tone,
    string Title,
    string Detail,
    bool ShowCreate,
    bool CreateEnabled,
    string CreateText,
    bool ShowActions,
    bool MountVisible,
    string MountText,
    bool MountEnabled,
    bool MountIsAcceptRollback,
    bool OpenEnabled,
    bool CloseEnabled,
    bool ShowUsage,
    double UsageFraction,
    string UsageText,
    string? DriverNote,
    bool ReformatEnabled,
    bool DeleteEnabled,
    bool AutoMountEnabled,
    bool TpmShown,
    TpmAction TpmAction,
    bool PhraseVisible,
    bool PhraseEnabled,
    bool StrictVisible,
    string TpmButtonText,
    bool TpmButtonEnabled,
    bool UnbindVisible,
    bool UnbindEnabled);

/// <summary>The legacy Vault page's Refresh() state ladder, as a pure function.</summary>
internal static class VaultPresenter
{
    public static VaultView Present(VaultFacts f)
    {
        string badge, title, detail;
        Tone tone;
        bool create = false, actions = false, mountVisible = false;

        if (!f.Enabled)
        {
            (badge, tone, title, detail) = ("OFF", Tone.Neutral, "Vault disabled",
                "Create one below — creating arms the feature.");
            create = true;
        }
        else if (!f.ImageExists)
        {
            (badge, tone, title, detail) = ("NO VAULT", Tone.Neutral, "No vault yet",
                "An encrypted drive that only exists while your key is present.");
            create = true;
        }
        else if (f.State == VaultState.SealedDead)
        {
            (badge, tone, title, detail) = ("SEALED — DEAD", Tone.Danger, "Permanently sealed",
                "Both key slots fell out of the rotation window — this vault cannot be " +
                "recovered. Reformat is the only path.");
            actions = true;
        }
        else if (f.State == VaultState.Corrupt)
        {
            (badge, tone, title, detail) = ("CORRUPT", Tone.Danger, "Image unreadable",
                "Bad header/manifest or a read error — retries on the next verify; " +
                "reformat if it persists.");
            actions = true;
        }
        else if (f.State == VaultState.RolledBack)
        {
            (badge, tone, title, detail) = ("ROLLED BACK", Tone.Danger, "Image rolled back",
                "Older than the last attested state — a rolled-back copy or a " +
                "restored backup. Accept it, or put the newer image back.");
            actions = mountVisible = true; // the mount slot hosts the accept action
        }
        else if (f.State == VaultState.TpmLocked)
        {
            (badge, tone, title, detail) = ("TPM LOCKED", Tone.Danger, "Bound to another machine",
                f.HasRecovery
                    ? "This machine's TPM can't unwrap the vault — enter the " +
                      "recovery phrase below, or reformat."
                    : "Strict-bound and the TPM won't answer — reformat is the only path.");
            actions = true;
        }
        else if (f.State == VaultState.Mounted)
        {
            (badge, tone, title, detail) = ("MOUNTED", Tone.Ok, $"Mounted at {f.MountPoint}",
                "Writes encrypt as they land — pull the key and it force-dismounts.");
            actions = mountVisible = true;
        }
        else if (f.State == VaultState.Unsealed)
        {
            (badge, tone, title, detail) = ("UNSEALED", Tone.Warn, "Unsealed — not mounted",
                f.DriverPresent ? "Volume key in memory — mount to open the drive."
                                : "The Dokany driver is missing, so it can't mount yet.");
            actions = mountVisible = true;
        }
        else if (f.State == VaultState.NeedsDriver)
        {
            (badge, tone, title, detail) = ("NEEDS DRIVER", Tone.Warn, "Needs the Dokany driver",
                "The image is unsealed but can't mount — install Dokany, then retry.");
            actions = mountVisible = true;
        }
        else
        {
            (badge, tone, title, detail) = ("SEALED", Tone.Neutral, "Sealed",
                f.KeyVerified
                    ? "Closed for this session — Unseal to reopen it, or " +
                      "pull and reinsert the key."
                    : "Insert your key to unlock the vault.");
            actions = true;
            mountVisible = f.KeyVerified; // "Unseal" — reopen under the held secret
        }

        bool mounted = f.State == VaultState.Mounted;
        double frac = 0;
        string usageText = "";
        if (mounted && f.Usage is (long used, long total))
        {
            frac = total > 0 ? (double)used / total : 0;
            usageText = $"{used / (1024 * 1024)} MB of {total / (1024 * 1024)} MB";
        }

        string mountText = f.State switch
        {
            VaultState.Mounted => "Dismount",
            VaultState.RolledBack => "Accept rolled-back state",
            VaultState.Sealed => "Unseal",
            _ => "Mount",
        };

        // Machine binding — live only with an image + the feature on.
        bool tpmShown = f.Enabled && f.ImageExists;
        bool open = f.State is VaultState.Unsealed or VaultState.Mounted or VaultState.NeedsDriver;
        TpmAction tpmAction;
        bool phraseVisible = false, phraseEnabled = false, strictVisible = false,
            tpmEnabled = false, unbindVisible = false, unbindEnabled = false;
        string tpmText;
        if (f.State == VaultState.TpmLocked)
        {
            tpmAction = TpmAction.UnlockWithPhrase;
            phraseVisible = phraseEnabled = f.HasRecovery;
            tpmText = "Unlock with phrase";
            tpmEnabled = f.HasRecovery;
        }
        else if (f.NeedsRebind)
        {
            // Opened via the phrase while the TPM was unreachable — offer
            // the re-bind so a live TPM re-wraps the pepper.
            tpmAction = TpmAction.Rebind;
            tpmText = "Re-bind to this machine";
            tpmEnabled = f.TpmAvailable;
            unbindVisible = true;
            unbindEnabled = open;
        }
        else if (f.TpmBound)
        {
            tpmAction = TpmAction.None;
            tpmText = "Bound to this machine";
            unbindVisible = true;
            unbindEnabled = open;
        }
        else
        {
            bool canBind = f.TpmAvailable && open && f.KeyVerified;
            tpmAction = TpmAction.Bind;
            phraseVisible = true;
            phraseEnabled = canBind;
            strictVisible = true;
            tpmText = f.TpmAvailable ? "Bind to this machine" : "No TPM on this machine";
            tpmEnabled = canBind;
        }

        return new VaultView(badge, tone, title, detail,
            ShowCreate: create,
            CreateEnabled: f.KeyVerified,
            CreateText: f.KeyVerified ? "Create vault" : "Insert key to create",
            ShowActions: actions,
            MountVisible: mountVisible,
            MountText: mountText,
            MountEnabled: f.State is VaultState.Unsealed or VaultState.Mounted
                or VaultState.NeedsDriver or VaultState.RolledBack
                || (f.State == VaultState.Sealed && f.KeyVerified),
            MountIsAcceptRollback: f.State == VaultState.RolledBack,
            OpenEnabled: mounted,
            // Something open to close — a user-seal on Sealed would be a no-op.
            CloseEnabled: f.State is VaultState.Unsealed or VaultState.Mounted
                or VaultState.NeedsDriver,
            ShowUsage: mounted,
            UsageFraction: frac,
            UsageText: usageText,
            // Warn before create too — a first-timer with no image must see
            // the driver gap before clicking Create, not after.
            DriverNote: !f.DriverPresent ? f.DriverHint ?? "Dokany driver missing" : null,
            ReformatEnabled: f.KeyVerified,
            DeleteEnabled: f.ImageExists,
            AutoMountEnabled: f.Enabled,
            TpmShown: tpmShown,
            TpmAction: tpmAction,
            PhraseVisible: phraseVisible,
            PhraseEnabled: phraseEnabled,
            StrictVisible: strictVisible,
            TpmButtonText: tpmText,
            TpmButtonEnabled: tpmEnabled,
            UnbindVisible: unbindVisible,
            UnbindEnabled: unbindEnabled);
    }
}

/// <summary>Unlock-policy and lock-mode copy for the Protection page.</summary>
internal static class ProtectionPresenter
{
    public static readonly (UnlockPolicy Policy, string Label, string Help)[] Policies =
    {
        (UnlockPolicy.KeyOrPassphrase, "Key or phrase", "Either your key or the recovery phrase unlocks."),
        (UnlockPolicy.KeyAndPassphrase, "Key + phrase", "Two factors: the key AND the phrase."),
        (UnlockPolicy.KeyOnly, "Key only", "Only the physical key unlocks."),
    };

    /// <summary>Whichever warnings currently apply — legacy UpdatePolicyWarning.</summary>
    public static IReadOnlyList<string> Warnings(UnlockPolicy policy, bool privateDesktop)
    {
        var parts = new List<string>();
        if (policy != UnlockPolicy.KeyOrPassphrase)
            parts.Add("A lost key under this policy is a real lockout — only the dev " +
                      "panic combo or Task Manager can recover.");
        if (privateDesktop)
            parts.Add("Private desktop: if the screen ever strands blank, " +
                      "run cryptokey --release-desktop.");
        return parts;
    }

    public static string IdleText(int minutes) => minutes == 0 ? "Off" : $"{minutes} min";
}

internal enum ActivityKind
{
    General,
    Security,
    Key,
    Vault,
}

internal sealed record ActivityItem(string Time, string Message, ActivityKind Kind, Tone Tone);

/// <summary>Turns raw guard log lines into typed, colored feed items.</summary>
internal static class ActivityPresenter
{
    private static readonly string[] SecurityWords =
    {
        "security event", "tamper", "clone", "intruder", "flap", "storm", "unreadable",
        "fail-closed", "failed attempt", "panic", "os-lock", "supervisor lost",
    };

    public static ActivityItem Parse(string line)
    {
        string time = "", msg = line.Trim();
        if (msg.StartsWith('['))
        {
            int close = msg.IndexOf(']');
            if (close > 0)
            {
                time = msg[1..close];
                // File backfill carries "MM-dd HH:mm:ss" — keep the clock part.
                int sp = time.LastIndexOf(' ');
                if (sp >= 0)
                    time = time[(sp + 1)..];
                msg = msg[(close + 1)..].Trim();
            }
        }
        string lower = msg.ToLowerInvariant();
        ActivityKind kind;
        Tone tone;
        if (SecurityWords.Any(lower.Contains))
            (kind, tone) = (ActivityKind.Security, Tone.Danger);
        else if (lower.Contains("vault"))
            (kind, tone) = (ActivityKind.Vault, Tone.Signal);
        else if (lower.StartsWith("locked") || lower.Contains("lock ("))
            (kind, tone) = (ActivityKind.Key, Tone.Danger);
        else if (lower.StartsWith("unlocked") || lower.Contains("verified"))
            (kind, tone) = (ActivityKind.Key, Tone.Ok);
        else if (lower.Contains("key") || lower.Contains("keyfile") || lower.Contains("lock"))
            (kind, tone) = (ActivityKind.Key, Tone.Neutral);
        else if (lower.Contains("fail") || lower.Contains("error") || lower.Contains("denied"))
            (kind, tone) = (ActivityKind.General, Tone.Warn);
        else
            (kind, tone) = (ActivityKind.General, Tone.Neutral);
        return new ActivityItem(time, msg, kind, tone);
    }

    public static bool Matches(ActivityItem item, ActivityKind? filter, string query)
        => (filter == null || item.Kind == filter)
           && (query.Length == 0 || item.Message.Contains(query, StringComparison.OrdinalIgnoreCase));
}
