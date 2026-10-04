using System.Diagnostics;

namespace CryptoKey;

/// <summary>
/// Persistent guard supervisor — `cryptokey watchdog --parent &lt;pid&gt;`.
/// Heartbeats the guard over the cryptokey-ctl pipe's `status` command every
/// ~750ms; three consecutive failed beats (~2s) declare death. A guard that
/// died while LOCKED gets the fail-closed response: release the input
/// desktop, LockWorkStation, respawn. An unlocked death gets respawn only.
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
    private const int DeathBeats = 3;
    private const int MaxFastRespawnFails = 5;

    private static string LogPath => Path.Combine(ConfigStore.ConfigDir, "watchdog.log");
    private static string OldLogPath => Path.Combine(ConfigStore.ConfigDir, "watchdog.log.1");

    public static int Run(int parentPid)
    {
        using var mutex = new Mutex(true, MutexName, out bool createdNew);
        if (!createdNew)
            return 0; // single instance — a second spawner just exits

        using var stop = new EventWaitHandle(false, EventResetMode.ManualReset, StopEventName);
        // A leftover SET event from a previous Stop() must not insta-kill us.
        stop.Reset();

        Log($"watchdog up (parent pid {parentPid}).");

        int fails = 0;
        int respawnFails = 0;
        bool wasLocked = false;
        DateTime nextRespawnAt = DateTime.MinValue;

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

            if (++fails < DeathBeats)
                continue;

            // Death declared. Fail-closed only when the guard was locked:
            // a lock surface (or its desktop) may outlive the process.
            if (wasLocked)
            {
                Log("guard died while LOCKED — fail-closed: release desktop, lock workstation, respawn.");
                ReleaseDesktop();
                NativeMethods.LockWorkStation();
            }
            else if (fails == DeathBeats)
            {
                Log("guard heartbeat lost.");
            }

            if (!File.Exists(ConfigStore.ConfigPath))
            {
                if (fails == DeathBeats)
                    Log("no config on disk — nothing to respawn; idle.");
                continue;
            }
            if (DateTime.UtcNow < nextRespawnAt)
                continue;

            if (TryRespawn())
            {
                Log("guard respawned.");
                fails = 0;
                respawnFails = 0;
                wasLocked = false;
            }
            else
            {
                respawnFails++;
                if (respawnFails >= MaxFastRespawnFails)
                {
                    Log("respawn failing — locking workstation; retrying every 30s.");
                    NativeMethods.LockWorkStation();
                    nextRespawnAt = DateTime.UtcNow.AddSeconds(30);
                }
                else
                {
                    nextRespawnAt = DateTime.UtcNow.AddSeconds(2);
                }
            }
        }
    }

    private static bool TryRespawn()
    {
        try
        {
            // `guard` = tray daemon. Inherits the watchdog's integrity level —
            // an elevated guard spawned an elevated watchdog, so respawns
            // stay elevated.
            Process? p = Process.Start(new ProcessStartInfo(
                Environment.ProcessPath ?? Application.ExecutablePath, "guard")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            });
            return p != null;
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
    public void Ensure(int parentPid)
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
            Process.Start(new ProcessStartInfo(
                Environment.ProcessPath ?? Application.ExecutablePath,
                $"watchdog --parent {parentPid}")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            });
            _log("Watchdog spawned.");
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
