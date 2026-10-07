using System.IO.Pipes;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Xunit;

// The suite shares one redirected config dir + one test platform bundle —
// classes must not race each other's Saves/Loads.
[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace CryptoKey.Tests;

/// <summary>
/// Redirect ConfigStore's root into a per-run temp dir AND install the test
/// platform bundle before ANY test code runs. Platform.Services is ambient —
/// first Init wins for the run — and every crypto test reaches ConfigStore
/// through statics (CreateNew, MatchSecret, RotateSecret), so a collection
/// fixture would race test ordering. A module initializer has no ordering
/// hazard.
///
/// The assert fails the whole run loudly if production ever stops honoring
/// the variable — the failure mode that once wrote test data into the
/// real user profile.
/// </summary>
internal static class TestInit
{
    public static string Dir { get; } = Path.Combine(
        Path.GetTempPath(), "ckcfg-" + Guid.NewGuid().ToString("N"));

    /// <summary>
    /// The third-copy backup lives OUTSIDE <see cref="Dir"/> — a config-dir
    /// wipe is exactly the case the third copy exists for, so co-locating
    /// them in the test bundle would make the wipe tests meaningless.
    /// </summary>
    public static string ThirdCopyPath { get; } = Path.Combine(
        Path.GetTempPath(), "ckcfg3-" + Guid.NewGuid().ToString("N"),
        "config-backup.json");

    [ModuleInitializer]
    public static void RedirectConfigRoot()
    {
        Environment.SetEnvironmentVariable("CRYPTOKEY_CONFIG_ROOT", Dir);
        Platform.Init(TestPlatform.Services);
        if (!ConfigStore.ConfigDir.StartsWith(Dir, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                $"Config root redirect failed — got {ConfigStore.ConfigDir}");
    }
}

/// <summary>
/// Null/temp platform bundle for tests: file-system paths under <see
/// cref="TestInit.Dir"/>, an identity protector (no DPAPI on the test
/// machines — the envelope's attestation MAC is what's under test, not the
/// OS seal), and no-op impls for every OS-facing seam.
/// </summary>
internal static class TestPlatform
{
    public static PlatformServices Services => new()
    {
        Paths = new TestPaths(),
        Protector = new TestProtector(),
        Usb = new TestUsbEnumerator(),
        KeyMonitors = new TestKeyMonitorFactory(),
        Ipc = new TestIpcSecurity(),
        SingleInstance = new TestSingleInstance(),
        StopSignals = new TestStopSignals(),
        LockPolicies = new NullLockPolicies(),
        Capture = new NullCaptureService(),
        SystemActions = new TestSystemActions(),
        ConfigBackup = new FileConfigBackup(TestInit.ThirdCopyPath),
        KeyfileAttrs = new NoopKeyfileAttrs(),
        AppLifetime = new TestAppLifetime(),
        Surfaces = new TestLockSurfaceFactory(),
        EnrollmentExtras = new NoopEnrollmentExtras(),
        UserAlerts = new ConsoleUserAlerts(),
        Cues = new NullCues(),
        VaultMounts = new TestVaultMounter(),
        VaultTpm = NullVaultTpm.Shared,
    };

    private sealed class TestPaths : IPlatformPaths
    {
        public string ConfigDir => TestInit.Dir;
    }

    /// <summary>
    /// Reversible-but-trivial "protection" — tag ‖ SHA-256(data) ‖ data, so
    /// corrupted or truncated blobs reject exactly like DPAPI tamper
    /// detection, without depending on an OS store.
    /// </summary>
    private sealed class TestProtector : IKeyProtector
    {
        private static readonly byte[] Tag = "TESTPROT"u8.ToArray();
        private const int HashLen = 32;

        public byte[] Protect(byte[] data, byte[] entropy)
        {
            byte[] blob = new byte[Tag.Length + HashLen + data.Length];
            Buffer.BlockCopy(Tag, 0, blob, 0, Tag.Length);
            Buffer.BlockCopy(SHA256.HashData(data), 0, blob, Tag.Length, HashLen);
            Buffer.BlockCopy(data, 0, blob, Tag.Length + HashLen, data.Length);
            return blob;
        }

        public byte[] Unprotect(byte[] data, byte[] entropy)
        {
            if (data.Length <= Tag.Length + HashLen
                || !data.AsSpan(0, Tag.Length).SequenceEqual(Tag))
                throw new CryptographicException("test envelope tag mismatch");
            ReadOnlySpan<byte> payload = data.AsSpan(Tag.Length + HashLen);
            if (!CryptographicOperations.FixedTimeEquals(
                    data.AsSpan(Tag.Length, HashLen), SHA256.HashData(payload)))
                throw new CryptographicException("test envelope corrupted");
            return payload.ToArray();
        }
    }

    internal sealed class TestUsbEnumerator : IUsbEnumerator
    {
        /// <summary>Attached disks — tests push/clear; the suite is non-parallel.</summary>
        public static List<UsbDisk> Disks { get; } = new();
        public List<UsbDisk> Enumerate() => Disks;
    }

    private sealed class TestKeyMonitorFactory : IKeyMonitorFactory
    {
        public KeyMonitorHandle Create(string targetSerial)
            => new(new TestKeyMonitor(), new TestDispatcher());
    }

    private sealed class TestKeyMonitor : IKeyMonitor
    {
        public event Action<bool>? PresenceChanged { add { } remove { } }
        public event Action<UsbDisk?>? PresenceChecked { add { } remove { } }
        public event Action<string>? ErrorLogged { add { } remove { } }
        public void SetPollInterval(int ms) { }
        public void SetTargetSerial(string serial) { }
        public void Dispose() { }
    }

    private sealed class TestDispatcher : IUiDispatcher
    {
        public void Post(Action work) => work();
        public T Send<T>(Func<T> work) => work();
    }

    private sealed class TestIpcSecurity : IIpcSecurity
    {
        public bool Elevated => false;
        public NamedPipeServerStream CreatePipe(out bool integrityLabeled)
        {
            integrityLabeled = false;
            return new NamedPipeServerStream(IpcServer.PipeName,
                PipeDirection.InOut,
                NamedPipeServerStream.MaxAllowedServerInstances,
                PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        }
    }

    private sealed class TestSingleInstance : ISingleInstance
    {
        private static readonly HashSet<string> Held = new();
        private static readonly object Gate = new();

        public IDisposable? Acquire(string name, bool waitForRelease)
        {
            var deadline = DateTime.UtcNow.AddSeconds(waitForRelease ? 30 : 0);
            do
            {
                lock (Gate)
                {
                    if (Held.Add(name))
                        return new Handle(name);
                }
                if (waitForRelease)
                    Thread.Sleep(50);
            }
            while (waitForRelease && DateTime.UtcNow < deadline);
            return null;
        }

        public bool IsHeld(string name)
        {
            lock (Gate) return Held.Contains(name);
        }

        private sealed class Handle : IDisposable
        {
            private readonly string _name;
            public Handle(string name) => _name = name;
            public void Dispose()
            {
                lock (Gate) Held.Remove(_name);
            }
        }
    }

    private sealed class TestStopSignals : IStopSignalFactory
    {
        private static bool _raised;

        public IStopSignalWaiter OpenWaiter() => new Waiter();
        public void Reset() => _raised = false;
        public void Signal() => _raised = true;

        private sealed class Waiter : IStopSignalWaiter
        {
            public bool Wait(int ms)
            {
                var deadline = DateTime.UtcNow.AddMilliseconds(ms);
                while (DateTime.UtcNow < deadline && !_raised)
                    Thread.Sleep(10);
                return _raised;
            }
            public void Dispose() { }
        }
    }

    private sealed class TestSystemActions : ISystemActions
    {
        public void LockScreen() { }
        public uint IdleMilliseconds() => 0;
        public void ReleaseInputDesktop() { }
    }

    private sealed class TestAppLifetime : IAppLifetime
    {
        public void Exit() { }
    }

    /// <summary>In-memory mount stand-in — records mounts, pretends a driver exists.</summary>
    private sealed class TestVaultMounter : IVaultMounter
    {
        public bool DriverPresent => true;
        public string? DriverHint => null;

        public IVaultMount? Mount(VaultVolume volume, string mountPoint, out string? error)
        {
            error = null;
            return new TestMount(mountPoint);
        }

        private sealed class TestMount : IVaultMount
        {
            public TestMount(string mp) => MountPoint = mp;
            public string MountPoint { get; }
            public event Action? Detached { add { } remove { } }
            public void Dispose() { }
        }
    }

    internal sealed class TestLockSurfaceFactory : ILockSurfaceFactory
    {
        /// <summary>Last surface the guard built — tests drive/observe it.</summary>
        public static TestLockSurface? Last { get; private set; }

        public ILockSurface Create(bool securePreferred, bool devMode)
            => Last = new TestLockSurface(securePreferred);
    }

    internal sealed class TestLockSurface : ILockSurface
    {
        private readonly bool _overlay;
        private Action<char[]>? _submitted;
        public TestLockSurface(bool overlay) => _overlay = overlay;

        public bool IsOverlay => _overlay;
        public string? EngageError => null;
        public event Action<char[]>? PassphraseSubmitted
        {
            add => _submitted += value;
            remove => _submitted -= value;
        }
        public event Action? PanicRequested { add { } remove { } }
        public event Action<string>? SecurityEvent { add { } remove { } }

        // Recorded surface state — the guard's backoff mirrors land here.
        public int FailedAttempts { get; private set; }
        public DateTime? CooldownUntil { get; private set; }
        public string? LastStatus { get; private set; }

        /// <summary>Raise a phrase submit as the real surface would.</summary>
        public void Submit(string text) => _submitted?.Invoke(text.ToCharArray());

        public bool Engage() => true;
        public bool Disengage() => true;
        public void ReleaseInput() { }
        public void ReassertClip() { }
        public void SetAnimations(bool enabled) { }
        public void SetStatus(string message) => LastStatus = message;
        public void ResetStatus() { }
        public void SetPassphraseLength(int len) { }
        public void SetFailedAttempts(int count) => FailedAttempts = count;
        public void SetCooldown(DateTime? until) => CooldownUntil = until;
        public void Dispose() { }
    }
}
