using System.Text.Json;
using Microsoft.Win32;

namespace CryptoKey;

/// <summary>
/// Lock-time policy garnish: while the guard is locked, three HKCU policy
/// DWORDs remove the affordances a casual attacker would reach for —
/// Task Manager (kill path), Sign out/Switch user (the last unsealed
/// SAS-level escape), and Start-menu power buttons. In overlay mode this
/// is more than cosmetic: CAD → Task Manager → end-process was the
/// classic lock's clean kill path, and these values close it on standard
/// images. (CAD "Switch user" survives — HideFastUserSwitching is an
/// HKLM-only policy, outside user-mode scope.)
///
/// The restore contract is the whole feature: each value's prior state is
/// persisted to lockpolicies.json before we touch it — kind + raw value,
/// verbatim for any registry type — so a GPO/admin-set value goes back to
/// exactly what it was, an absent value is deleted, and a Policies subkey
/// that only exists because we created it is dropped once empty.
///
/// Restore is read-gated: values are checked with a read-only open first,
/// so images that deny the user writes to HKCU\...\Policies (but still
/// allow reads) get a clean no-op instead of a permanently-kept backup.
///
/// Honest scope: removes the GUI affordance, not the capability — taskkill,
/// Stop-Process, Process Explorer and the Ctrl+Alt+Del power button are
/// unaffected (documented in security-model.md, not overclaimed).
/// </summary>
internal static class LockPolicies
{
    private sealed record Policy(string SubKey, string ValueName);

    /// <summary>
    /// One captured prior. Kind is a <see cref="RegistryValueKind"/> name,
    /// "Absent" (no value), or "Unreadable" (read threw — captured so a
    /// later delete is a deliberate fail-open, not a silent assumption).
    /// Value holds the raw prior as JSON for verbatim restore; a legacy
    /// backup is plain int? and upconverts on read.
    /// </summary>
    private sealed record PriorEntry(string Kind, JsonElement? Value, bool SubKeyExisted);

    private static readonly Policy[] Policies =
    [
        new(@"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr"),
        new(@"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoLogoff"),
        new(@"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoClose"),
    ];

    private static string BackupPath => Path.Combine(ConfigStore.ConfigDir, "lockpolicies.json");

    /// <summary>
    /// Capture priors (first apply only — an existing backup means they're
    /// already captured; re-reading would back up our own 1s), then set
    /// all three values to 1. Every step is best-effort: garnish must
    /// never take the guard down.
    /// </summary>
    public static void Apply(Action<string> log)
    {
        try
        {
            if (!File.Exists(BackupPath))
            {
                var priors = new Dictionary<string, PriorEntry>();
                foreach (Policy p in Policies)
                    priors[p.ValueName] = CapturePrior(p);
                // Same flushed-tmp+move pattern as config.json.
                AtomicFile.WriteAllText(BackupPath, JsonSerializer.Serialize(priors));
            }
            int applied = 0;
            foreach (Policy p in Policies)
            {
                try
                {
                    using RegistryKey key = Registry.CurrentUser.CreateSubKey(p.SubKey);
                    key.SetValue(p.ValueName, 1, RegistryValueKind.DWord);
                    applied++;
                }
                catch (Exception ex)
                {
                    log($"policy {p.ValueName} not applied ({ex.Message}).");
                }
            }
            log(applied == Policies.Length
                ? "Lock policies applied (Task Manager, sign-out, power hidden while locked)."
                : $"Lock policies partially applied ({applied}/{Policies.Length}) — " +
                  "hardened/locked-down images deny user writes to Policies keys; " +
                  "run the guard elevated for full coverage.");
        }
        catch (Exception ex)
        {
            log($"Lock policy backup failed ({ex.Message}) — skipping policies.");
        }
    }

    /// <summary>
    /// Put every policy back to its captured prior — absent priors get
    /// deleted, present priors restored verbatim in their original kind —
    /// then drop the backup. No backup on disk = nothing was applied = a
    /// no-op. Also the crash path: a respawned guard finds a stale backup
    /// here and restores before anything else.
    /// </summary>
    public static void Restore(Action<string> log)
    {
        if (!File.Exists(BackupPath))
            return;
        Dictionary<string, PriorEntry>? priors = LoadPriors(log);
        int failed = 0;
        foreach (IGrouping<string, Policy> group in Policies.GroupBy(p => p.SubKey))
        {
            using RegistryKey? readKey = Registry.CurrentUser.OpenSubKey(group.Key);
            if (readKey == null)
                continue; // subkey gone — any priors inside died with it
            foreach (Policy p in group)
            {
                // Read-gate: if the value isn't there, there is nothing to
                // do — never touch a writable handle for it. On read-only
                // Policies keys this keeps restore a clean no-op instead
                // of a permanently-failing write attempt.
                if (readKey.GetValue(p.ValueName) == null)
                    continue;
                try
                {
                    PriorEntry entry =
                        priors != null && priors.TryGetValue(p.ValueName, out PriorEntry? e)
                            ? e
                            : new PriorEntry("Absent", null, SubKeyExisted: true);
                    using RegistryKey? wkey =
                        Registry.CurrentUser.OpenSubKey(group.Key, writable: true);
                    if (wkey == null)
                        continue; // subkey vanished between opens — value died with it
                    if (entry.Kind == "Absent" || entry.Kind == "Unreadable"
                        || !TryMaterialize(entry, out object? value, out RegistryValueKind kind))
                    {
                        // Prior unknown or unrepresentable — fail open:
                        // clear our value rather than leave a restriction
                        // we can't fully account for.
                        wkey.DeleteValue(p.ValueName, throwOnMissingValue: false);
                        if (entry.Kind == "Unreadable")
                            log($"policy {p.ValueName} prior was unreadable — cleared our value.");
                    }
                    else
                        wkey.SetValue(p.ValueName, value!, kind);
                }
                catch (Exception ex)
                {
                    failed++;
                    log($"policy {p.ValueName} restore failed ({ex.Message}).");
                }
            }
            // If the subkey only exists because we created it, drop it
            // once it's empty again — leave no trace.
            if (readKey.ValueCount == 0 && readKey.SubKeyCount == 0 && priors != null
                && group.All(p => priors.TryGetValue(p.ValueName, out PriorEntry? e) && !e.SubKeyExisted))
                TryDeleteEmptySubKey(group.Key);
        }
        if (failed == 0)
        {
            try { File.Delete(BackupPath); }
            catch (Exception) { }
            log("Lock policies restored.");
        }
        else
        {
            // Keep the backup — a later (e.g. elevated) start retries the
            // restore instead of losing the priors to a partial cleanup.
            log($"Lock policy restore incomplete ({failed} failed) — backup kept for retry.");
        }
    }

    /// <summary>
    /// Read a policy's prior: verbatim kind + raw value when present,
    /// Absent when the value (or subkey) isn't there, Unreadable when the
    /// read itself throws.
    /// </summary>
    private static PriorEntry CapturePrior(Policy p)
    {
        try
        {
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(p.SubKey);
            if (key == null)
                return new PriorEntry("Absent", null, SubKeyExisted: false);
            object? raw = key.GetValue(
                p.ValueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            if (raw == null)
                return new PriorEntry("Absent", null, SubKeyExisted: true);
            return new PriorEntry(
                key.GetValueKind(p.ValueName).ToString(),
                JsonSerializer.SerializeToElement(raw),
                SubKeyExisted: true);
        }
        catch (Exception)
        {
            // Can't prove absent — restore deletes ours fail-open.
            return new PriorEntry("Unreadable", null, SubKeyExisted: true);
        }
    }

    /// <summary>Parse the backup — current schema, then the legacy int? map.</summary>
    private static Dictionary<string, PriorEntry>? LoadPriors(Action<string> log)
    {
        string json;
        try { json = File.ReadAllText(BackupPath); }
        catch (Exception ex)
        {
            log($"Lock policy backup unreadable ({ex.Message}) — clearing values.");
            return null;
        }
        try
        {
            var v2 = JsonSerializer.Deserialize<Dictionary<string, PriorEntry>>(json);
            if (v2 != null)
                return v2;
        }
        catch (Exception) { }
        try
        {
            var v1 = JsonSerializer.Deserialize<Dictionary<string, int?>>(json);
            if (v1 != null)
                return v1.ToDictionary(
                    kv => kv.Key,
                    kv => kv.Value.HasValue
                        ? new PriorEntry("DWord",
                            JsonSerializer.SerializeToElement(kv.Value.Value),
                            SubKeyExisted: true)
                        : new PriorEntry("Absent", null, SubKeyExisted: true));
        }
        catch (Exception) { }
        // Corrupt backup: priors unknowable — fail open (remove our
        // values) rather than leave the user restricted forever.
        log("Lock policy backup unreadable — clearing values.");
        return null;
    }

    /// <summary>Rebuild the raw registry value from its captured JSON + kind.</summary>
    private static bool TryMaterialize(
        PriorEntry entry, out object? value, out RegistryValueKind kind)
    {
        value = null;
        kind = RegistryValueKind.Unknown;
        if (entry.Value is not JsonElement je)
            return false;
        try
        {
            switch (entry.Kind)
            {
                case "DWord":
                    value = je.GetInt32();
                    kind = RegistryValueKind.DWord;
                    return true;
                case "QWord":
                    value = je.GetInt64();
                    kind = RegistryValueKind.QWord;
                    return true;
                case "String":
                    value = je.GetString();
                    kind = RegistryValueKind.String;
                    return true;
                case "ExpandString":
                    value = je.GetString();
                    kind = RegistryValueKind.ExpandString;
                    return true;
                case "MultiString":
                    value = je.EnumerateArray().Select(x => x.GetString() ?? "").ToArray();
                    kind = RegistryValueKind.MultiString;
                    return true;
                case "Binary":
                    value = je.GetBytesFromBase64();
                    kind = RegistryValueKind.Binary;
                    return true;
                default:
                    return false;
            }
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>Remove an empty subkey we created — cosmetic, best-effort.</summary>
    private static void TryDeleteEmptySubKey(string subKey)
    {
        try
        {
            int cut = subKey.LastIndexOf('\\');
            using RegistryKey? parent =
                Registry.CurrentUser.OpenSubKey(subKey[..cut], writable: true);
            parent?.DeleteSubKey(subKey[(cut + 1)..], throwOnMissingSubKey: false);
        }
        catch (Exception) { }
    }
}
