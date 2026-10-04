using System.Text.Json;
using Microsoft.Win32;

namespace CryptoKey;

/// <summary>
/// Lock-time policy garnish: while the guard is locked, three HKCU policy
/// DWORDs remove the affordances a casual attacker would reach for —
/// Task Manager (kill path), Sign out/Switch user (the last unsealed
/// SAS-level escape), and Start-menu power buttons.
///
/// The restore contract is the whole feature: each value's prior state is
/// persisted to lockpolicies.json before we touch it — null = was absent
/// (deleted on restore), a number = restored verbatim. A GPO/admin-set
/// value goes back to exactly what it was.
///
/// Honest scope: removes the GUI affordance, not the capability — taskkill,
/// Stop-Process, Process Explorer and the Ctrl+Alt+Del power button are
/// unaffected (documented in security-model.md, not overclaimed).
/// </summary>
internal static class LockPolicies
{
    private sealed record Policy(string SubKey, string ValueName);

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
                var priors = new Dictionary<string, int?>();
                foreach (Policy p in Policies)
                    priors[p.ValueName] = ReadDword(p);
                // Same atomic tmp+move pattern as config.json.
                string tmp = BackupPath + ".tmp";
                File.WriteAllText(tmp, JsonSerializer.Serialize(priors));
                File.Move(tmp, BackupPath, overwrite: true);
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
    /// deleted, numbered priors restored verbatim — then drop the backup.
    /// No backup on disk = nothing was applied = a no-op.
    /// </summary>
    public static void Restore(Action<string> log)
    {
        if (!File.Exists(BackupPath))
            return;
        Dictionary<string, int?>? priors = null;
        try
        {
            priors = JsonSerializer.Deserialize<Dictionary<string, int?>>(
                File.ReadAllText(BackupPath));
        }
        catch (Exception ex)
        {
            // Corrupt backup: priors unknowable — fail open (remove our
            // values) rather than leave the user restricted forever.
            log($"Lock policy backup unreadable ({ex.Message}) — clearing values.");
        }
        int failed = 0;
        foreach (Policy p in Policies)
        {
            try
            {
                using RegistryKey? key = Registry.CurrentUser.OpenSubKey(p.SubKey, writable: true);
                if (key == null)
                    continue;
                if (priors != null && priors.TryGetValue(p.ValueName, out int? prior) && prior.HasValue)
                    key.SetValue(p.ValueName, prior.Value, RegistryValueKind.DWord);
                else
                    key.DeleteValue(p.ValueName, throwOnMissingValue: false);
            }
            catch (Exception ex)
            {
                failed++;
                log($"policy {p.ValueName} restore failed ({ex.Message}).");
            }
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
    /// Crash path: a respawned/relaunched guard finds a stale backup and
    /// restores — same no-op-when-absent contract as Restore.
    /// </summary>
    public static void RestoreIfPending(Action<string> log) => Restore(log);

    private static int? ReadDword(Policy p)
    {
        try
        {
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(p.SubKey);
            return key?.GetValue(p.ValueName) as int?;
        }
        catch (Exception)
        {
            return null; // treat unreadable as absent — restore will delete ours
        }
    }
}
