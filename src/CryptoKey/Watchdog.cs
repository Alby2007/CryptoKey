using System.Diagnostics;

namespace CryptoKey;

/// <summary>
/// Persistent guard supervisor — `cryptokey watchdog --parent &lt;pid&gt;`.
/// Heartbeats the guard over the cryptokey-ctl pipe's `status` command every
/// ~750ms. Death is declared when the watched process is gone AND the pipe
/// is silent (immediate), or when a live process misses 8 beats (~6s —
/// wider than the pipe's worst-case stall, so one stalled client can't fake
/// a death). A guard that died while LOCKED gets the fail-closed response:
/// release the input desktop, LockWorkStation, respawn. An unlocked death
/// gets respawn only. --dev/--classic are forwarded to every respawn.
///
/// Deliberately dumb: no config loading, no state machine, no UI — just a
/// heartbeat, a mutex, a stop event, a respawn, and a lock. Adoption is
/// automatic: any guard answering the pipe is "the guard", so an orphaned
/// watchdog simply keeps beating against whatever guard is live.
///
/// Honest limit (documented in security-model): `taskkill /f /im
/// cryptokey.exe` still kills both at once. This closes "kill one process",
/// not "knows the pair exists".
/// </summary>
internal static class Watchdog
{
    internal const string MutexName = @"Local\CryptoKeyWatchdog";
    internal const string StopEventName = @"Local\CryptoKeyWatchdogStop";

    private const int BeatMs = 750;
    private const int ReplyTimeoutMs = 500;
    // ~6s of silent heartbeats to call a live-but-wedged process dead —
    // deliberately wider than the pipe's worst-case stall (~5s read
    // timeout) so ONE stalled client can never fake a death.
    private const int DeathBeats = 8;
    private const int MaxFastRespawnFails = 5;
    // A freshly respawned guard needs a few seconds to stand the pipe up —
    // misses inside the grace window don't count toward the wedged budget.
    private const int RespawnGraceMs = 10_000;

    private static string LogPath => Path.Combine(ConfigStore.ConfigDir, "watchdog.log");
    private static string OldLogPath => Path.Combine(ConfigStore.ConfigDir, "watchdog.log.1");

    public static int Run(int parentPid, bool devMode, bool forceClassic)
    {
        using var mutex = new Mutex(true, MutexName, out bool createdNew);
        if (!createdNew)
            return 0; // single instance — a second spawner just exits

        // NOTE: no stop.Reset() here — the Supervisor resets the event
        // right before spawning. Resetting on this side would clear a
        // stand-down that lands between spawn and our first WaitOne and
        // respawn a guard that was explicitly quit.
        using var stop = new EventWaitHandle(false, EventResetMode.ManualReset, StopEventName);

        // Respawn the same guard we were launched beside — losing --dev
        // would strip the panic combo, losing --classic flips the lock mode.
        string respawnArgs = "guard"
            + (devMode ? " --dev" : "")
            + (forceClassic ? " --classic" : "");

        Log($"watchdog up (parent pid {parentPid}).");

        int fails = 0;
        int respawnFails = 0;
        bool wasLocked = false;
        int watchPid = parentPid;
        DateTime nextRespawnAt = DateTime.MinValue;
        DateTime respawnGraceUntil = DateTime.MinValue;

        while (true)
        {
            if (stop.WaitOne(BeatMs))
            {
                Log("stand-down received — exiting.");
                return 0;
            }

            string? reply;
            try { reply = IpcClient.Send("status", ReplyTimeoutMs); }
            catch (Exception) { reply = null; }

            if (reply != null && reply.StartsWith("ok", StringComparison.Ordinal))
            {
                if (fails > 0)
                    Log("guard heartbeat recovered.");
                fails = 0;
                respawnFails = 0;
                wasLocked = reply.Contains("state=locked");
                continue;
            }

            // Pipe missed. Process-gone + silent pipe = dead NOW; process
            // alive + silent pipe = possibly wedged — count to the wide
            // budget (any guard answering the pipe wins over the pid —
            // adoption stays automatic).
            bool newlyDead;
            if (!ParentAlive(watchPid))
            {
                newlyDead = fails < DeathBeats;
                fails = Math.Max(fails, DeathBeats);
            }
            else if (DateTime.UtcNow < respawnGraceUntil)
            {
                continue; // fresh spawn still standing its pipe up
            }
            else
            {
                newlyDead = ++fails == DeathBeats;
            }

            // Death declared — once per declaration, not per missed beat.
            // Fail-closed only when the guard was locked: a lock surface
            // (or its desktop) may outlive the process.
            if (newlyDead && wasLocked)
            {
                Log("guard died while LOCKED — fail-closed: release desktop, lock workstation, respawn.");
                ReleaseDesktop();
                NativeMethods.LockWorkStation();
            }
            else if (newlyDead)
            {
                Log("guard heartbeat lost.");
            }

            if (!File.Exists(ConfigStore.ConfigPath))
            {
                if (newlyDead)
                    Log("no config on disk — nothing to respawn; idle.");
                continue;
            }
            if (DateTime.UtcNow < nextRespawnAt)
                continue;

            // Counts attempts without a recovered heartbeat, not just spawn
            // errors — a spawn that dies again still escalates the backoff.
            respawnFails++;
            if (TryRespawn(respawnArgs, out int newPid))
            {
                Log("guard respawned.");
                watchPid = newPid;
                fails = 0;
                wasLocked = false;
                respawnGraceUntil = DateTime.UtcNow.AddMilliseconds(RespawnGraceMs);
                nextRespawnAt = DateTime.UtcNow.AddSeconds(2); // bound respawn cadence
            }
            else
            {
                Log($"respawn attempt #{respawnFails} failed.");
            }

            if (respawnFails >= MaxFastRespawnFails)
            {
                Log("respawn failing — locking workstation; retrying every 30s.");
                NativeMethods.LockWorkStation();
                nextRespawnAt = DateTime.UtcNow.AddSeconds(30);
            }
        }
    }

    /// <summary>Is the watched guard process still alive?</summary>
    private static bool ParentAlive(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return !p.HasExited;
        }
        catch (Exception)
        {
            return false; // gone, or the pid never existed
        }
    }

    private static bool TryRespawn(string args, out int pid)
    {
        pid = 0;
        try
        {
            // `guard` = tray daemon. Inherits the watchdog's integrity level —
            // an elevated guard spawned an elevated watchdog, so respawns
            // stay elevated.
            Process? p = Process.Start(new ProcessStartInfo(
                Environment.ProcessPath ?? Application.ExecutablePath, args)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            });
            if (p == null)
                return false;
            pid = p.Id;
            p.Dispose();
            return true;
        }
        catch (Exception ex)
        {
            Log($"respawn failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>Same rescue as --release-desktop — redundant with the per-engage lock watchdog by design.</summary>
    private static void ReleaseDesktop()
    {
        try
        {
            IntPtr h = NativeMethods.OpenDesktop("Default", 0, false,
                NativeMethods.DESKTOP_SWITCHDESKTOP);
            if (h != IntPtr.Zero)
            {
                if (NativeMethods.SwitchDesktop(h))
                    Log("input switched back to Default desktop.");
                NativeMethods.CloseDesktop(h);
            }
        }
        catch (Exception) { }
    }

    private static void Log(string message)
    {
        try
        {
            Directory.CreateDirectory(ConfigStore.ConfigDir);
            var fi = new FileInfo(LogPath);
            if (fi.Exists && fi.Length > 256 * 1024)
                File.Move(LogPath, OldLogPath, overwrite: true);
            File.AppendAllText(LogPath, $"[{DateTime.Now:MM-dd HH:mm:ss}] {message}\r\n");
        }
        catch (Exception) { /* logging must never take down the watchdog */ }
    }
}

/// <summary>
/// The guard's handle on its watchdog: probes the mutex for liveness,
/// spawns `cryptokey watchdog --parent &lt;pid&gt;` when absent (≈5s cadence
/// from GuardService), and sets the named stop event on every graceful exit
/// so the watchdog stands down instead of respawning.
/// </summary>
internal sealed class Supervisor
{
    private readonly Action<string> _log;

    public Supervisor(Action<string> log) => _log = log;

    public bool Alive
    {
        get
        {
            try
            {
                if (Mutex.TryOpenExisting(Watchdog.MutexName, out Mutex? m))
                {
                    m.Dispose();
                    return true;
                }
            }
            catch (Exception) { }
            return false;
        }
    }

    /// <summary>Spawn the watchdog if the mutex says none exists.</summary>
    public void Ensure(int parentPid, bool devMode, bool forceClassic)
    {
        if (Alive)
            return;
        try
        {
            // Clear a stale stand-down before spawning — otherwise the new
            // watchdog would open a SET event and exit on its first beat.
            using var stop = new EventWaitHandle(false, EventResetMode.ManualReset,
                Watchdog.StopEventName);
            stop.Reset();
        }
        catch (Exception) { }
        try
        {
            // The watchdog forwards these flags to every respawned guard —
            // a respawn must come back with the same panic combo / lock mode.
            Process? p = Process.Start(new ProcessStartInfo(
                Environment.ProcessPath ?? Application.ExecutablePath,
                $"watchdog --parent {parentPid}"
                    + (devMode ? " --dev" : "")
                    + (forceClassic ? " --classic" : ""))
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            });
            if (p != null)
            {
                p.Dispose();
                _log("Watchdog spawned.");
            }
            else
            {
                _log("Watchdog spawn failed: no process started.");
            }
        }
        catch (Exception ex)
        {
            _log($"Watchdog spawn failed: {ex.Message}");
        }
    }

    /// <summary>Stand the watchdog down — called on every graceful exit path.</summary>
    public void Stop()
    {
        try
        {
            using var stop = EventWaitHandle.OpenExisting(Watchdog.StopEventName);
            stop.Set();
        }
        catch (Exception) { /* no watchdog — nothing to stop */ }
    }
}
