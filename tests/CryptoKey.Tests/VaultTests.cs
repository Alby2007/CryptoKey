using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace CryptoKey.Tests;

/// <summary>
/// Pure-layer vault suite: format round-trips, the two-generation ratchet
/// window, chunk tamper detection, torn-manifest fallback, and the tree/IO
/// semantics the Dokan adapter leans on. No driver needed — the mount seam
/// is a test fake.
/// </summary>
public class VaultTests : IDisposable
{
    private readonly string _dir = Path.Combine(
        Path.GetTempPath(), "ckvault-" + Guid.NewGuid().ToString("N"));

    public VaultTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (Exception) { }
    }

    private string Img(string name = "vault.ckv") => Path.Combine(_dir, name);

    private static byte[] Kek(byte[] secret, byte[] salt)
        => VaultFormat.DeriveKek(secret, salt);

    private static byte[] KekFor(string path, byte[] secret)
        => Kek(secret, VaultVolume.PeekHeader(path)!.Salt);

    private static VaultVolume Open(string path, byte[] secret)
    {
        byte[] kek = KekFor(path, secret);
        try
        {
            Assert.True(VaultVolume.TryOpen(path, kek, out VaultVolume? vol,
                out VaultOpenError err, out _), $"open failed: {err}");
            Assert.NotNull(vol);
            return vol;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    // --------------------------------------------------------------- format

    [Fact]
    public void Header_round_trips()
    {
        var slots = new[]
        {
            new VaultKeySlot(7, RandomNumberGenerator.GetBytes(12),
                RandomNumberGenerator.GetBytes(48)),
            new VaultKeySlot(6, RandomNumberGenerator.GetBytes(12),
                RandomNumberGenerator.GetBytes(48)),
        };
        var header = new VaultHeader(VaultFormat.FormatVersion, 0,
            RandomNumberGenerator.GetBytes(VaultFormat.SaltLen), slots,
            41, 40, 1234, (ulong)VaultFormat.DataOffset);

        VaultHeader back = VaultFormat.ReadHeader(VaultFormat.WriteHeader(header));
        Assert.Equal(header.Version, back.Version);
        Assert.Equal(header.Salt, back.Salt);
        Assert.Equal((41ul, 40ul), (back.ManifestSeq0, back.ManifestSeq1));
        Assert.Equal(1234u, back.ChunkCount);
        Assert.Equal(VaultFormat.DataOffset, (long)back.ChunkRegionBase);
        for (int i = 0; i < 2; i++)
        {
            Assert.Equal(slots[i].RotationGen, back.KeySlots[i].RotationGen);
            Assert.Equal(slots[i].Nonce, back.KeySlots[i].Nonce);
            Assert.Equal(slots[i].WrappedKey, back.KeySlots[i].WrappedKey);
        }
    }

    [Fact]
    public void Bad_magic_rejects()
    {
        byte[] page = new byte[VaultFormat.HeaderSize];
        "CKVAULT\x02"u8.CopyTo(page); // wrong version byte in magic
        Assert.Throws<VaultException>(() => VaultFormat.ReadHeader(page));
    }

    [Fact]
    public void Keyslot_wrap_unwraps_under_same_kek_only()
    {
        byte[] secret = TestDisk.RandomSecret();
        byte[] salt = RandomNumberGenerator.GetBytes(VaultFormat.SaltLen);
        byte[] kek = Kek(secret, salt);
        byte[] volKey = RandomNumberGenerator.GetBytes(VaultFormat.VolKeyLen);
        VaultKeySlot slot = VaultFormat.WrapVolumeKey(kek, volKey, 5, 0);

        byte[]? back = VaultFormat.UnwrapVolumeKey(kek, slot, 0);
        Assert.Equal(volKey, back);

        // Wrong KEK → tag rejection → null. Wrong slot index AAD → null too.
        byte[] wrongKek = RandomNumberGenerator.GetBytes(32);
        Assert.Null(VaultFormat.UnwrapVolumeKey(wrongKek, slot, 0));
        Assert.Null(VaultFormat.UnwrapVolumeKey(kek, slot, 1));
        // Wrong gen AAD → null.
        var genShifted = new VaultKeySlot(6, slot.Nonce, slot.WrappedKey);
        Assert.Null(VaultFormat.UnwrapVolumeKey(kek, genShifted, 0));
    }

    // ------------------------------------------------------------- lifecycle

    [Fact]
    public void Create_then_reopen_under_same_secret()
    {
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        using (VaultVolume.Create(path, 16, secret, 1)) { }

        using VaultVolume vol = Open(path, secret);
        Assert.True(vol.TryGet("\\", out VaultNode root) && root.IsDir);
    }

    [Fact]
    public void Prev_gen_slot_opens_after_rotation_slide()
    {
        string path = Img();
        byte[] genA = TestDisk.RandomSecret();
        byte[] genB = TestDisk.RandomSecret();
        using (var vol = VaultVolume.Create(path, 16, genA, 1))
        {
            // Rotation edge: service slides slots to {genB, genA}.
            byte[] salt = vol.Salt;
            vol.ReWrapKeys(Kek(genB, salt), Kek(genA, salt), 2, 1);
        }
        // Current secret opens slot 0…
        using (var v2 = Open(path, genB)) { }
        // …and the previous-generation secret opens slot 1.
        using (var v3 = Open(path, genA)) { }
    }

    [Fact]
    public void Two_missed_rotations_seal_permanently()
    {
        string path = Img();
        byte[] genA = TestDisk.RandomSecret();
        using (var vol = VaultVolume.Create(path, 16, genA, 1))
        {
            byte[] salt = vol.Salt;
            // Two rotation edges: window becomes {C, B} — A is dead.
            byte[] genB = TestDisk.RandomSecret(), genC = TestDisk.RandomSecret();
            vol.ReWrapKeys(Kek(genB, salt), Kek(genA, salt), 2, 1); // {B, A}
            vol.ReWrapKeys(Kek(genC, salt), Kek(genB, salt), 3, 2); // {C, B}
        }
        byte[] kekA = KekFor(path, genA);
        Assert.False(VaultVolume.TryOpen(path, kekA, out _,
            out VaultOpenError err, out _));
        Assert.Equal(VaultOpenError.Sealed, err);
        CryptographicOperations.ZeroMemory(kekA);
    }

    [Fact]
    public void Chunk_tamper_throws_integrity_error()
    {
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        byte[] payload = Enumerable.Range(0, 2048).Select(i => (byte)(i % 251)).ToArray();
        using (var vol = VaultVolume.Create(path, 16, secret, 1))
        {
            Assert.Equal(VaultResult.Ok, vol.CreateFile("\\note.bin", out _));
            Assert.Equal(VaultResult.Ok, vol.Write("\\note.bin", 0, payload, out int w));
            Assert.Equal(payload.Length, w);
            vol.Flush();
        }

        // Corrupt one byte of chunk ciphertext in the image (chunk region
        // starts at DataOffset; the file's first chunk is wherever the
        // allocator put it — flip every chunk's tag byte at the first
        // allocated offset is fragile; instead corrupt chunk 0's tag).
        int chunkId;
        using (var vol = Open(path, secret))
        {
            Assert.True(vol.TryGet("\\note.bin", out VaultNode n));
            chunkId = n.Chunks[0];
        }
        using (var fs = new FileStream(path, FileMode.Open, FileAccess.ReadWrite))
        {
            long off = VaultFormat.ChunkOffset(VaultFormat.DataOffset, chunkId);
            fs.Position = off + VaultFormat.NonceLen; // flip a tag byte
            int b = fs.ReadByte();
            fs.Position = off + VaultFormat.NonceLen;
            fs.WriteByte((byte)(b ^ 0xFF));
        }
        using (var vol = Open(path, secret))
        {
            byte[] dst = new byte[2048];
            Assert.Throws<VaultIntegrityException>(() => vol.Read("\\note.bin", 0, dst));
        }
    }

    [Fact]
    public void Torn_manifest_falls_back_to_prior_epoch()
    {
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        using (var vol = VaultVolume.Create(path, 16, secret, 1))
        {
            vol.CreateFile("\\first.txt", out _);
            vol.Write("\\first.txt", 0, "one"u8.ToArray(), out _);
            vol.Flush(); // seq 2 → slot 0
            vol.CreateFile("\\second.txt", out _);
            vol.Write("\\second.txt", 0, "two"u8.ToArray(), out _);
            vol.Flush(); // seq 3 → slot 1
        }

        // Trash the newest slot (slot = seq & 1 → seq 3 lives in slot 1).
        using (var fs = new FileStream(path, FileMode.Open, FileAccess.ReadWrite))
        {
            fs.Position = VaultFormat.ManifestBase + VaultFormat.ManifestSlotSize;
            byte[] garbage = RandomNumberGenerator.GetBytes(128);
            fs.Write(garbage);
        }

        using (var vol = Open(path, secret))
        {
            Assert.True(vol.TryGet("\\first.txt", out _));   // epoch seq 2 survived
            Assert.False(vol.TryGet("\\second.txt", out _)); // torn seq 3 rolled back
        }
    }

    // ----------------------------------------------------------------- tree

    [Fact]
    public void Crud_rename_truncate_and_listing()
    {
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        using var vol = VaultVolume.Create(path, 16, secret, 1);

        Assert.Equal(VaultResult.Ok, vol.CreateDir("\\docs", out _));
        Assert.Equal(VaultResult.Ok, vol.CreateFile("\\docs\\a.txt", out _));
        Assert.Equal(VaultResult.Ok,
            vol.Write("\\docs\\a.txt", 0, "hello vault"u8.ToArray(), out _));

        byte[] buf = new byte[64];
        int n = vol.Read("\\docs\\a.txt", 0, buf);
        Assert.Equal("hello vault", Encoding.UTF8.GetString(buf, 0, n));

        // Rename in place + move.
        Assert.Equal(VaultResult.Ok, vol.Move("\\docs\\a.txt", "\\docs\\b.txt", false));
        Assert.False(vol.TryGet("\\docs\\a.txt", out _));
        Assert.True(vol.TryGet("\\docs\\b.txt", out _));

        // Truncate shrinks.
        Assert.Equal(VaultResult.Ok, vol.SetLength("\\docs\\b.txt", 5));
        n = vol.Read("\\docs\\b.txt", 0, buf);
        Assert.Equal("hello", Encoding.UTF8.GetString(buf, 0, n));

        // Dir listing shows the child once.
        var kids = vol.List("\\docs");
        Assert.Single(kids);
        Assert.Equal("b.txt", kids[0].Name);

        // Root sees the dir.
        Assert.Single(vol.List("\\"));

        // Delete non-empty dir is refused; empty succeeds.
        Assert.Equal(VaultResult.NotEmpty, vol.Delete("\\docs"));
        Assert.Equal(VaultResult.Ok, vol.Delete("\\docs\\b.txt"));
        Assert.Equal(VaultResult.Ok, vol.Delete("\\docs"));
    }

    [Fact]
    public void Paths_are_case_insensitive_but_preserve_case()
    {
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        using var vol = VaultVolume.Create(path, 16, secret, 1);

        vol.CreateDir("\\MiXeD", out _);
        vol.CreateFile("\\mixed\\File.TXT", out _);

        Assert.True(vol.TryGet("\\MIXED\\file.txt", out VaultNode n));
        Assert.Equal("File.TXT", n.Name);
        Assert.Equal(VaultResult.AlreadyExists, vol.CreateFile("\\mixed\\FILE.TXT", out _));
        Assert.Equal(VaultResult.Ok, vol.Write("\\Mixed\\FILE.txt", 0, "x"u8.ToArray(), out _));
        byte[] buf = new byte[4];
        Assert.Equal(1, vol.Read("\\mIxEd\\fIlE.tXt", 0, buf));
    }

    [Fact]
    public void Freelist_reuses_freed_chunks()
    {
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        using var vol = VaultVolume.Create(path, 16, secret, 1);

        byte[] payload = new byte[VaultFormat.ChunkPayload * 3];
        RandomNumberGenerator.Fill(payload);
        vol.CreateFile("\\tmp.bin", out _);
        vol.Write("\\tmp.bin", 0, payload, out _);
        Assert.True(vol.TryGet("\\tmp.bin", out VaultNode n1));
        var firstIds = n1.Chunks.Where(c => c >= 0).ToList();
        Assert.Equal(3, firstIds.Count);

        vol.Delete("\\tmp.bin");
        (int alloc, int highWater, int freed) = vol.DebugChunkStats();
        Assert.Equal(3, freed);
        Assert.Equal(3, highWater);

        // Same content → allocator should hand the freed ids back (sorted reuse).
        vol.CreateFile("\\tmp2.bin", out _);
        vol.Write("\\tmp2.bin", 0, payload, out _);
        Assert.True(vol.TryGet("\\tmp2.bin", out VaultNode n2));
        Assert.Equal(firstIds.OrderBy(x => x), n2.Chunks.OrderBy(x => x));
        (alloc, highWater, freed) = vol.DebugChunkStats();
        Assert.Equal(3, highWater); // high-water didn't grow
    }

    [Fact]
    public void Capacity_is_enforced()
    {
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        // 16 MiB image → ~(16-8.25) MiB of chunk region ≈ ~1980 chunks.
        using var vol = VaultVolume.Create(path, 16, secret, 1);
        int chunkCount = vol.ChunkCount;
        byte[] payload = new byte[VaultFormat.ChunkPayload];
        RandomNumberGenerator.Fill(payload);

        vol.CreateFile("\\fill.bin", out _);
        long offset = 0;
        VaultResult res = VaultResult.Ok;
        for (int i = 0; i < chunkCount + 4; i++)
        {
            res = vol.Write("\\fill.bin", offset, payload, out _);
            if (res != VaultResult.Ok)
                break;
            offset += VaultFormat.ChunkPayload;
        }
        Assert.Equal(VaultResult.Full, res);
    }

    [Fact]
    public void Manifest_encrypts_filenames()
    {
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        using (var vol = VaultVolume.Create(path, 16, secret, 1))
        {
            vol.CreateDir("\\TopSecretDir", out _);
            vol.CreateFile("\\TopSecretDir\\Plans.txt", out _);
        } // dispose flushes the manifest

        byte[] raw = File.ReadAllBytes(path);
        byte[] nameBytes = "TopSecretDir"u8.ToArray();
        for (int i = 0; i + nameBytes.Length <= raw.Length; i++)
            Assert.False(raw.AsSpan(i, nameBytes.Length).SequenceEqual(nameBytes),
                $"plaintext filename leaked at offset {i}");
    }

    [Fact]
    public void Sparse_writes_and_seek_reads()
    {
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        using var vol = VaultVolume.Create(path, 16, secret, 1);
        vol.CreateFile("\\sparse.bin", out _);
        // Write 4 bytes at offset 1 MiB — the hole must read as zeros.
        vol.Write("\\sparse.bin", 1024 * 1024, "end!"u8.ToArray(), out _);
        Assert.True(vol.TryGet("\\sparse.bin", out VaultNode n));
        Assert.Equal(1024 * 1024 + 4, n.Size);
        byte[] buf = new byte[8];
        Assert.Equal(8, vol.Read("\\sparse.bin", 1024 * 1024 - 4, buf));
        Assert.Equal(new byte[] { 0, 0, 0, 0, (byte)'e', (byte)'n', (byte)'d', (byte)'!' }, buf);
    }

    // --------------------------------------------------------------- service

    private KeyConfig VaultConfig(string path)
    {
        KeyConfig c = TestDisk.NewConfig(TestDisk.RandomSecret());
        c.Guard.VaultEnabled = true;
        c.Guard.VaultImagePath = path;
        return c;
    }

    [Fact]
    public void Service_consumes_and_zeroes_the_secret()
    {
        KeyConfig c = VaultConfig(Img());
        using var vault = new VaultService(c, new TestMounter(), _ => { });
        byte[] secret = TestDisk.RandomSecret();
        vault.KeyVerified(secret, 3);
        Assert.All(secret, b => Assert.Equal(0, b)); // caller's copy was zeroed
    }

    [Fact]
    public void Service_seal_unseal_cycle()
    {
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig c = VaultConfig(path);
        var mounter = new TestMounter();
        using var vault = new VaultService(c, mounter, _ => { });

        Assert.Equal(VaultState.NoImage, vault.State);
        vault.KeyVerified(secret.ToArray(), 1);
        Assert.True(vault.TryCreate(16, out string err), err);
        Assert.True(vault.WaitForPendingOps()); // unseal/mount land async
        Assert.Equal(VaultState.Mounted, vault.State); // auto-mount on, driver present (test fake)

        vault.KeyGone();
        Assert.Equal(VaultState.Sealed, vault.State); // image exists, secret dropped

        vault.KeyVerified(secret.ToArray(), 1);
        Assert.True(vault.WaitForPendingOps());
        Assert.Equal(VaultState.Mounted, vault.State); // unsealed + re-mounted
    }

    [Fact]
    public void Unmount_during_inflight_mount_fences_it()
    {
        // TryUnmount with _mount still null used to return without fencing —
        // the in-flight MountBody then committed anyway and the vault stayed
        // mounted. The _unmountSeq fence must drop the late mount.
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig c = VaultConfig(path);
        var mounter = new TestMounter { BlockInMount = true };
        using var vault = new VaultService(c, mounter, _ => { });

        vault.KeyVerified(secret.ToArray(), 1);
        Assert.True(vault.TryCreate(16, out string err), err);
        Assert.True(mounter.EnteredMount.Wait(TimeSpan.FromSeconds(10)));

        Assert.True(vault.TryUnmount(out _)); // nothing mounted yet — must still fence
        mounter.ReleaseMount.Set();
        Assert.True(vault.WaitForPendingOps());

        Assert.Equal(VaultState.Unsealed, vault.State); // the late mount was dropped
    }

    [Fact]
    public void Service_sealed_dead_when_secret_not_in_window()
    {
        string path = Img();
        byte[] genA = TestDisk.RandomSecret();
        using (VaultVolume.Create(path, 16, genA, 1)) { }
        KeyConfig c = VaultConfig(path);
        using var vault = new VaultService(c, new TestMounter(), _ => { });
        vault.KeyVerified(TestDisk.RandomSecret(), 9); // gen-9 secret knows nothing of gen 1
        Assert.True(vault.WaitForPendingOps());
        Assert.Equal(VaultState.SealedDead, vault.State);
    }

    [Fact]
    public void Service_disabled_without_flag()
    {
        KeyConfig c = VaultConfig(Img());
        c.Guard.VaultEnabled = false;
        using var vault = new VaultService(c, new TestMounter(), _ => { });
        Assert.Equal(VaultState.Disabled, vault.State);
        byte[] secret = TestDisk.RandomSecret();
        vault.KeyVerified(secret, 1); // no-op when disabled
        Assert.All(secret, b => Assert.Equal(0, b)); // still consumed + zeroed
        Assert.Equal(VaultState.Disabled, vault.State);
    }

    /// <summary>In-memory IVaultMounter for service-level tests.</summary>
    private sealed class TestMounter : IVaultMounter
    {
        public bool DriverPresent => true;
        public string? DriverHint => null;
        public int MountCount;
        public bool BlockInMount;
        public readonly ManualResetEventSlim EnteredMount = new();
        public readonly ManualResetEventSlim ReleaseMount = new();

        public IVaultMount? Mount(VaultVolume volume, string mountPoint, out string? error)
        {
            error = null;
            EnteredMount.Set();
            if (BlockInMount)
                ReleaseMount.Wait(TimeSpan.FromSeconds(10));
            MountCount++;
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

    private sealed class NoDriverMounter : IVaultMounter
    {
        public bool DriverPresent => false;
        public string? DriverHint => "needs the Dokany driver";
        public IVaultMount? Mount(VaultVolume volume, string mountPoint, out string? error)
        {
            error = DriverHint;
            return null;
        }
    }

    [Fact]
    public void Service_reports_needs_driver_honestly()
    {
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig c = VaultConfig(path);
        using var vault = new VaultService(c, new NoDriverMounter(), _ => { });
        vault.KeyVerified(secret.ToArray(), 1);
        Assert.True(vault.TryCreate(16, out _));
        Assert.True(vault.WaitForPendingOps());
        Assert.Equal(VaultState.NeedsDriver, vault.State); // unsealed but no driver
        Assert.False(vault.DriverPresent);
    }

    [Fact]
    public void User_seal_holds_against_generation_edge()
    {
        // A user-initiated Close must not be resurrected by the next feed:
        // a fresh-generation verify would otherwise reopen the sealed image
        // immediately (no throttle on that path).
        string path = Img();
        KeyConfig c = VaultConfig(path);
        var mounter = new TestMounter();
        using var vault = new VaultService(c, mounter, _ => { });

        vault.KeyVerified(TestDisk.RandomSecret(), 1);
        Assert.True(vault.TryCreate(16, out string err), err);
        Assert.True(vault.WaitForPendingOps());
        Assert.Equal(VaultState.Mounted, vault.State);

        Assert.True(vault.TrySeal(out string serr), serr);
        Assert.Equal(VaultState.Sealed, vault.State);

        vault.KeyVerified(TestDisk.RandomSecret(), 2); // rotation edge
        Assert.True(vault.WaitForPendingOps());
        Assert.Equal(VaultState.Sealed, vault.State); // held — not reopened
    }

    [Fact]
    public void User_seal_holds_against_same_gen_reverify()
    {
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig c = VaultConfig(path);
        using var vault = new VaultService(c, new TestMounter(), _ => { });

        vault.KeyVerified(secret.ToArray(), 1);
        Assert.True(vault.TryCreate(16, out _));
        Assert.True(vault.WaitForPendingOps());

        Assert.True(vault.TrySeal(out _));
        vault.KeyVerified(secret.ToArray(), 1); // same-gen poll re-verify
        Assert.True(vault.WaitForPendingOps());
        Assert.Equal(VaultState.Sealed, vault.State);
        Assert.True(vault.SecretHeld); // secret stays held — Unseal can use it
    }

    [Fact]
    public void TryUnseal_reopens_a_user_sealed_vault()
    {
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig c = VaultConfig(path);
        using var vault = new VaultService(c, new TestMounter(), _ => { });

        vault.KeyVerified(secret.ToArray(), 1);
        Assert.True(vault.TryCreate(16, out _));
        Assert.True(vault.WaitForPendingOps());

        Assert.True(vault.TrySeal(out _));
        Assert.Equal(VaultState.Sealed, vault.State);

        Assert.True(vault.TryUnseal(out string uerr), uerr);
        Assert.True(vault.WaitForPendingOps());
        Assert.Equal(VaultState.Mounted, vault.State); // reopened + auto-mounted
    }

    [Fact]
    public void KeyGone_lifts_the_user_seal()
    {
        // The seal holds for the session — a key pull is the session edge.
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig c = VaultConfig(path);
        using var vault = new VaultService(c, new TestMounter(), _ => { });

        vault.KeyVerified(secret.ToArray(), 1);
        Assert.True(vault.TryCreate(16, out _));
        Assert.True(vault.WaitForPendingOps());

        Assert.True(vault.TrySeal(out _));
        vault.KeyGone();
        Assert.Equal(VaultState.Sealed, vault.State);

        vault.KeyVerified(secret.ToArray(), 1); // key back — auto-open resumes
        Assert.True(vault.WaitForPendingOps());
        Assert.Equal(VaultState.Mounted, vault.State);
    }

    [Fact]
    public void User_seal_works_from_needs_driver()
    {
        // The reported bug: create without Dokany lands on NeedsDriver and
        // "Close vault" was a silent no-op. TrySeal must actually seal it.
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig c = VaultConfig(path);
        using var vault = new VaultService(c, new NoDriverMounter(), _ => { });

        vault.KeyVerified(secret.ToArray(), 1);
        Assert.True(vault.TryCreate(16, out _));
        Assert.True(vault.WaitForPendingOps());
        Assert.Equal(VaultState.NeedsDriver, vault.State);

        Assert.True(vault.TrySeal(out string serr), serr);
        Assert.Equal(VaultState.Sealed, vault.State);

        vault.KeyVerified(TestDisk.RandomSecret(), 2); // stays sealed on re-verify
        Assert.True(vault.WaitForPendingOps());
        Assert.Equal(VaultState.Sealed, vault.State);
    }

    [Fact]
    public void Rotation_slide_keeps_both_generations_openable()
    {
        string path = Img();
        byte[] genA = TestDisk.RandomSecret();
        KeyConfig c = VaultConfig(path);
        var mounter = new TestMounter();
        var logs = new List<string>();
        using var vault = new VaultService(c, mounter, logs.Add);

        vault.KeyVerified(genA.ToArray(), 1);
        Assert.True(vault.TryCreate(16, out string cerr), cerr);
        Assert.True(vault.WaitForPendingOps());

        // Rotation edge: the drive now presents gen B — service slides slots.
        byte[] genB = TestDisk.RandomSecret();
        vault.KeyVerified(genB.ToArray(), 2);
        Assert.True(vault.WaitForPendingOps());

        // The service holds the image open; drop it to probe slots directly.
        vault.KeyGone();
        VaultHeader peeked = VaultVolume.PeekHeader(path)!;
        Assert.True(peeked != null);
        Assert.Equal((2u, 1u),
            (peeked.KeySlots[0].RotationGen, peeked.KeySlots[1].RotationGen));
        // Both secrets must still open the image (slot A = B, slot B = A).
        using (Open(path, genB)) { }
        using (Open(path, genA)) { }

        // Re-verify B so the service re-opens the image, then one more edge:
        // window becomes {C, B} — A falls out.
        vault.KeyVerified(genB.ToArray(), 2);
        Assert.True(vault.WaitForPendingOps()); // unseal must land before the next edge
        byte[] genC = TestDisk.RandomSecret();
        vault.KeyVerified(genC.ToArray(), 3);
        Assert.True(vault.WaitForPendingOps());
        vault.KeyGone();
        using (Open(path, genC)) { }
        using (Open(path, genB)) { }
        byte[] kekA = KekFor(path, genA);
        Assert.False(VaultVolume.TryOpen(path, kekA, out _, out _, out _));
        CryptographicOperations.ZeroMemory(kekA);
    }

    // ------------------------------------------------------------ regressions

    [Fact]
    public void Dispose_flushes_dirty_manifest()
    {
        // Regression: Dispose set _disposed before the final flush, so a dirty
        // manifest never persisted — last-session mutations vanished silently.
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        using (var v = VaultVolume.Create(path, 16, secret, 1))
        {
            v.CreateFile("\\lost.txt", out _);
            v.Write("\\lost.txt", 0, "data"u8.ToArray(), out _);
            // No explicit Flush — relying on Dispose's flush-on-close.
        }
        using (var vol = Open(path, secret))
            Assert.True(vol.TryGet("\\lost.txt", out _));
    }

    [Fact]
    public void Sparse_grow_then_shrink_does_not_throw()
    {
        // Regression: grow leaves Chunks empty; shrink computed a negative
        // RemoveRange count → ArgumentOutOfRangeException.
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        using var vol = VaultVolume.Create(path, 16, secret, 1);
        Assert.Equal(VaultResult.Ok, vol.CreateFile("\\f.bin", out _));
        Assert.Equal(VaultResult.Ok, vol.SetLength("\\f.bin", 10 * 1024 * 1024));
        Assert.Equal(VaultResult.Ok, vol.SetLength("\\f.bin", 5 * 1024 * 1024));
        Assert.True(vol.TryGet("\\f.bin", out VaultNode n));
        Assert.Equal(5 * 1024 * 1024, n.Size);
        byte[] buf = new byte[8];
        Assert.Equal(8, vol.Read("\\f.bin", 5 * 1024 * 1024 - 8, buf));
        Assert.All(buf, b => Assert.Equal(0, b)); // sparse tail reads zeros
    }

    [Fact]
    public void Case_only_rename_updates_display_name()
    {
        // Regression: dst.Equals(src, IgnoreCase) returned early without
        // updating node.Name — the casing change silently dropped.
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        using var vol = VaultVolume.Create(path, 16, secret, 1);
        vol.CreateFile("\\Foo.TXT", out _);
        Assert.Equal(VaultResult.Ok, vol.Move("\\Foo.TXT", "\\foo.txt", false));
        Assert.True(vol.TryGet("\\FOO.txt", out VaultNode n));
        Assert.Equal("foo.txt", n.Name); // new casing preserved
    }

    [Fact]
    public void Write_reports_partial_bytes_on_full()
    {
        // Regression: the early Full return left `written` at 0 even though
        // earlier chunks in the same call had landed.
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        using var vol = VaultVolume.Create(path, 16, secret, 1);
        vol.CreateFile("\\fill.bin", out _);
        byte[] big = new byte[(vol.ChunkCount + 4) * VaultFormat.ChunkPayload];
        RandomNumberGenerator.Fill(big);
        Assert.Equal(VaultResult.Full, vol.Write("\\fill.bin", 0, big, out int w));
        Assert.Equal(vol.ChunkCount * VaultFormat.ChunkPayload, w);
    }

    [Fact]
    public void Torn_primary_header_heals_from_shadow()
    {
        // Regression: a single-copy header meant one torn write bricked the
        // image. The v2 shadow page carries a byte-identical backup; the
        // checksum catches a torn-but-plausible primary.
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        using (var vol = VaultVolume.Create(path, 16, secret, 1))
        {
            vol.CreateFile("\\keep.txt", out _);
            vol.Write("\\keep.txt", 0, "safe"u8.ToArray(), out _);
        }
        // Corrupt keyslot bytes in the PRIMARY page — magic/version intact,
        // so only the checksum catches it; the shadow must carry the open.
        using (var fs = new FileStream(path, FileMode.Open, FileAccess.ReadWrite))
        {
            fs.Position = 96; // inside key slot 1
            fs.WriteByte(0xFF);
        }
        using (var vol = Open(path, secret))
        {
            Assert.True(vol.TryGet("\\keep.txt", out _));
            byte[] buf = new byte[4];
            Assert.Equal(4, vol.Read("\\keep.txt", 0, buf));
            Assert.Equal("safe"u8.ToArray(), buf);
        }
    }

    [Fact]
    public void Service_reports_corrupt_when_manifest_dead()
    {
        // Both header pages AND both manifest slots gone → Corrupt, not
        // SealedDead — reformat-worthy but distinct from a dead key window.
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        using (VaultVolume.Create(path, 16, secret, 1)) { }
        using (var fs = new FileStream(path, FileMode.Open, FileAccess.Write))
        {
            // Headers intact (key unwrap still succeeds); both manifest
            // slots dead → LoadManifest throws → Corrupt, not SealedDead.
            fs.Position = VaultFormat.ManifestBase;
            fs.Write(new byte[VaultFormat.ManifestSlots * VaultFormat.ManifestSlotSize]);
        }
        KeyConfig c = VaultConfig(path);
        using var vault = new VaultService(c, new TestMounter(), _ => { });
        vault.KeyVerified(secret.ToArray(), 1);
        Assert.True(vault.WaitForPendingOps());
        Assert.Equal(VaultState.Corrupt, vault.State);
    }

    [Fact]
    public void Old_format_image_reports_corrupt_not_sealed()
    {
        // A v1 image (or any header both pages reject) used to sit in Sealed
        // forever — the peek returned null and the state machine treated it
        // as transient. Peek now distinguishes "couldn't read" from
        // "rejected": a rejected header surfaces Corrupt.
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        using (VaultVolume.Create(path, 16, secret, 1)) { }

        // Forge a pre-v2 header: real magic, version 1. ReadHeader throws on
        // the version check before the checksum, so no recompute needed.
        byte[] page = new byte[VaultFormat.HeaderSize];
        using (var fs = new FileStream(path, FileMode.Open, FileAccess.ReadWrite))
        {
            int n = fs.Read(page, 0, page.Length);
            Assert.Equal(VaultFormat.HeaderSize, n);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(
                page.AsSpan(8), 1);
            fs.Position = 0;
            fs.Write(page, 0, page.Length);         // primary page = v1
            fs.Write(page, 0, page.Length);         // shadow region = v1 too
        }

        KeyConfig c = VaultConfig(path);
        using var vault = new VaultService(c, new TestMounter(), _ => { });
        vault.KeyVerified(secret.ToArray(), 1);
        // Synchronous — a rejected peek never reaches the async open.
        Assert.Equal(VaultState.Corrupt, vault.State);
    }

    // ------------------------------------------------------- crash orphans

    private static void BumpHighWater(VaultVolume vol, int plus)
    {
        // Simulate allocations the manifest forgot — the exact inconsistency
        // RebuildFreeList reclaims (reachable via reflection only: the real
        // writer never persists a self-inconsistent manifest).
        var f = typeof(VaultVolume).GetField("_highWater",
            System.Reflection.BindingFlags.NonPublic
                | System.Reflection.BindingFlags.Instance)!;
        f.SetValue(vol, (int)f.GetValue(vol)! + plus);
    }

    [Fact]
    public void Crash_discards_unflushed_allocations_cleanly()
    {
        // Write-through chunks land immediately; a crash before Flush leaves
        // them allocated-but-unreferenced. The persisted manifest's high-
        // water never covered them, so reopen stays consistent (no heal) and
        // the dead chunks recycle through the watermark naturally.
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        var vol = VaultVolume.Create(path, 16, secret, 1);
        vol.CreateFile("\\work.bin", out _);
        vol.Write("\\work.bin", 0,
            new byte[VaultFormat.ChunkPayload * 2], out _);
        vol.SimulateCrash(); // die before Flush — the manifest never saw the file

        using (var v2 = Open(path, secret))
        {
            Assert.Equal(0, v2.LastHealOrphans); // manifest was consistent
            Assert.False(v2.TryGet("\\work.bin", out _)); // node unflushed — gone
            // Recycled chunks are allocatable again — write + read back.
            v2.CreateFile("\\new.bin", out _);
            v2.Write("\\new.bin", 0, "recovered"u8.ToArray(), out _);
            byte[] buf = new byte[16];
            Assert.Equal(9, v2.Read("\\new.bin", 0, buf));
            Assert.Equal("recovered"u8.ToArray(), buf[..9]);
        }
    }

    [Fact]
    public void Heal_recovers_orphans_and_ignores_sparse_holes()
    {
        // Persist a manifest whose high-water accounts for chunks that are
        // neither referenced nor free — RebuildFreeList must reclaim them.
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        using (var vol = VaultVolume.Create(path, 16, secret, 1))
        {
            vol.CreateFile("\\b.bin", out _);
            // Sparse: write at offset 2 chunks in — chunk table carries a
            // -1 hole; chunks 0 and 1 land referenced.
            vol.Write("\\b.bin", 2L * VaultFormat.ChunkPayload,
                new byte[VaultFormat.ChunkPayload], out _);
            BumpHighWater(vol, 3); // three phantom allocations below hw
        } // Dispose flushes the inconsistent manifest

        using var v2 = Open(path, secret);
        Assert.Equal(3, v2.LastHealOrphans);
        (int alloc, int highWater, int freed) = v2.DebugChunkStats();
        Assert.Equal(1, alloc);      // b.bin's one real chunk (holes skipped)
        Assert.Equal(4, highWater);  // persisted 1 + the 3 phantoms
        Assert.Equal(3, freed);      // all phantoms reclaimed
    }

    [Fact]
    public void Duplicate_chunk_reference_fails_open_as_corrupt()
    {
        // A manifest that double-references a chunk would double-free and
        // double-alloc it — real corruption, fail loud instead of healing.
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        using (var vol = VaultVolume.Create(path, 16, secret, 1))
        {
            vol.CreateFile("\\dup.bin", out _);
            vol.Write("\\dup.bin", 0, new byte[VaultFormat.ChunkPayload], out _);
            Assert.True(vol.TryGet("\\dup.bin", out VaultNode n));
            n.Chunks.Add(n.Chunks[0]); // same physical chunk referenced twice
            vol.Flush();
        }
        byte[] kek = KekFor(path, secret);
        Assert.False(VaultVolume.TryOpen(path, kek, out _,
            out VaultOpenError err, out _));
        Assert.Equal(VaultOpenError.Corrupt, err);
        CryptographicOperations.ZeroMemory(kek);
    }

    [Fact]
    public void Garbage_free_entries_are_clamped_on_open()
    {
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        using (var vol = VaultVolume.Create(path, 16, secret, 1))
        {
            // Inject a garbage freelist entry (past the high-water) — only
            // reachable via reflection; it lands in the flushed manifest.
            var free = (SortedSet<int>)typeof(VaultVolume)
                .GetField("_free", System.Reflection.BindingFlags.NonPublic
                    | System.Reflection.BindingFlags.Instance)!
                .GetValue(vol)!;
            free.Add(vol.ChunkCount + 5); // past the region — impossible id
            vol.CreateFile("\\touch.txt", out _); // marks the manifest dirty
        } // Dispose flushes the tampered freelist

        using var v2 = Open(path, secret); // clamped on load — open succeeds
        (int alloc, int highWater, int freed) = v2.DebugChunkStats();
        Assert.Equal(0, alloc);
        Assert.Equal(0, freed); // nothing referenced, nothing orphaned
    }

    [Fact]
    public void Clamp_only_heal_persists_across_reopen()
    {
        // A freelist whose ONLY defect is garbage entries has no orphans —
        // the heal still dirtied the manifest, else it silently re-runs on
        // every open forever (the overwrite bug this regresses).
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        using (var vol = VaultVolume.Create(path, 16, secret, 1))
        {
            var free = (SortedSet<int>)typeof(VaultVolume)
                .GetField("_free", System.Reflection.BindingFlags.NonPublic
                    | System.Reflection.BindingFlags.Instance)!
                .GetValue(vol)!;
            free.Add(vol.ChunkCount + 5); // garbage entry, no orphans
            vol.CreateFile("\\touch.txt", out _); // force a manifest flush
        }

        using (var v2 = Open(path, secret))
        {
            Assert.Equal(0, v2.LastHealOrphans); // clamp ran, nothing orphaned
            var dirty = (bool)typeof(VaultVolume)
                .GetField("_dirty", System.Reflection.BindingFlags.NonPublic
                    | System.Reflection.BindingFlags.Instance)!
                .GetValue(v2)!;
            Assert.True(dirty); // the repaired freelist must persist on close
        }
    }

    [Fact]
    public void Clean_open_reports_no_heal_and_stays_clean()
    {
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        using (VaultVolume.Create(path, 16, secret, 1)) { }
        using (var vol = Open(path, secret))
        {
            Assert.Equal(0, vol.LastHealOrphans);
            Assert.Equal(1ul, vol.ManifestSeq);
        }
        // A clean open never dirtied the manifest — seq must not advance.
        using (var vol = Open(path, secret))
            Assert.Equal(1ul, vol.ManifestSeq);
    }

    [Fact]
    public void Healed_freelist_persists_across_reopen()
    {
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        using (var vol = VaultVolume.Create(path, 16, secret, 1))
        {
            vol.CreateFile("\\keep.bin", out _); // empty node — forces dirty
            BumpHighWater(vol, 1);             // one phantom alloc
        }

        using (var v2 = Open(path, secret))
            Assert.Equal(1, v2.LastHealOrphans); // heal ran + marked dirty
        // Dispose flushed the repaired freelist — next open is clean.
        using (var v3 = Open(path, secret))
            Assert.Equal(0, v3.LastHealOrphans);
    }

    // ------------------------------------------------------ epoch / rollback

    [Fact]
    public void Open_adopts_epoch_forward_and_flags_reattest()
    {
        // Image ahead of config (crash between flush and epoch save, or the
        // config came from an older backup) — the epoch adopts forward.
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        using (var vol = VaultVolume.Create(path, 16, secret, 1))
        {
            vol.CreateFile("\\f.txt", out _);
            vol.Write("\\f.txt", 0, "x"u8.ToArray(), out _);
            vol.Flush(); // seq 2 — past the create-time seq 1
        }
        KeyConfig c = VaultConfig(path); // VaultEpoch = 0
        int mutated = 0;
        var mounter = new TestMounter();
        using var vault = new VaultService(c, mounter, _ => { },
            () => mutated++);

        vault.KeyVerified(secret.ToArray(), 1);
        Assert.True(vault.WaitForPendingOps());
        Assert.Equal(VaultState.Mounted, vault.State);
        Assert.Equal(2ul, c.VaultEpoch);   // adopted the image's seq
        Assert.Equal(1, mutated);          // re-attest flagged
    }

    [Fact]
    public void Rolled_back_image_flags_and_holds()
    {
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        using (var vol = VaultVolume.Create(path, 16, secret, 1))
        {
            vol.CreateFile("\\f.txt", out _);
            vol.Flush(); // seq 2
        }
        KeyConfig c = VaultConfig(path);
        c.VaultEpoch = 10; // attested beyond the image — it looks rolled back
        var mounter = new TestMounter();
        var logs = new List<string>();
        using var vault = new VaultService(c, mounter, logs.Add);

        vault.KeyVerified(secret.ToArray(), 1);
        Assert.True(vault.WaitForPendingOps());
        Assert.Equal(VaultState.RolledBack, vault.State);
        Assert.Equal(0, mounter.MountCount); // never mounts a stale image
        Assert.Contains(logs, l => l.Contains("predates attested epoch"));

        // Same-gen re-verify is a no-op; a fresh edge re-detects (one log
        // per key cycle — no flap loop, Mount stays at zero throughout).
        vault.KeyVerified(secret.ToArray(), 1);
        vault.KeyVerified(secret.ToArray(), 2);
        Assert.Equal(VaultState.RolledBack, vault.State);
        vault.KeyGone();
        vault.KeyVerified(secret.ToArray(), 3);
        Assert.True(vault.WaitForPendingOps());
        Assert.Equal(VaultState.RolledBack, vault.State);
        Assert.Equal(0, mounter.MountCount);
    }

    [Fact]
    public void AcceptRollback_recovers_the_image()
    {
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        using (var vol = VaultVolume.Create(path, 16, secret, 1))
        {
            vol.CreateFile("\\f.txt", out _);
            vol.Flush();
        }
        KeyConfig c = VaultConfig(path);
        c.VaultEpoch = 10;
        using var vault = new VaultService(c, new TestMounter(), _ => { });

        vault.KeyVerified(secret.ToArray(), 1);
        Assert.True(vault.WaitForPendingOps());
        Assert.Equal(VaultState.RolledBack, vault.State);

        Assert.True(vault.AcceptRollback(out string err), err);
        Assert.Equal(2ul, c.VaultEpoch);   // epoch moved DOWN to the image's seq
        Assert.True(vault.WaitForPendingOps());
        Assert.Equal(VaultState.Mounted, vault.State); // re-opened + auto-mounted
    }

    [Fact]
    public void AcceptRollback_refuses_without_pending_rollback()
    {
        KeyConfig c = VaultConfig(Img()); // no image, nothing pending
        using var vault = new VaultService(c, new TestMounter(), _ => { });
        Assert.False(vault.AcceptRollback(out string err));
        Assert.NotEmpty(err);
    }

    [Fact]
    public void Reformat_resets_the_epoch()
    {
        // A reformatted image is seq 1 again — without the reset it would
        // read as rolled-back against the old high epoch forever.
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig c = VaultConfig(path);
        c.VaultEpoch = 42; // as if a long-lived vault had attested high
        var mounter = new TestMounter();
        using var vault = new VaultService(c, mounter, _ => { });

        vault.KeyVerified(secret.ToArray(), 1);
        Assert.True(vault.TryCreate(16, out string err), err);
        Assert.True(vault.WaitForPendingOps());
        Assert.Equal(1ul, c.VaultEpoch);  // reset to the fresh image's seq
        Assert.Equal(VaultState.Mounted, vault.State); // not RolledBack

        vault.KeyGone();
        vault.KeyVerified(secret.ToArray(), 1);
        Assert.True(vault.WaitForPendingOps());
        Assert.Equal(VaultState.Mounted, vault.State); // opens cleanly
    }

    [Fact]
    public void Sealed_through_rotation_recovers_under_prev_secret()
    {
        // Regression: a rotation landing while the vault was closed left
        // slots wrapping only the old generation — the new keyfile's KEK
        // unwrapped nothing and the image went SealedDead forever. The
        // service retains the displaced secret one cycle and falls back to
        // it, then re-wraps the slots into the current window.
        string path = Img();
        byte[] genA = TestDisk.RandomSecret();
        byte[] genB = TestDisk.RandomSecret();
        KeyConfig c = VaultConfig(path);
        var mounter = new TestMounter();
        var logs = new List<string>();
        using var vault = new VaultService(c, mounter, logs.Add);

        // Feed gen 1 with no image yet — the service holds A as current.
        vault.KeyVerified(genA.ToArray(), 1);
        Assert.Equal(VaultState.NoImage, vault.State);

        // The image appears out-of-band, wrapped under gen 1 — the service
        // hasn't opened it, and the drive has since rotated to gen 2.
        using (VaultVolume.Create(path, 16, genA, 1)) { }
        vault.KeyVerified(genB.ToArray(), 2); // cur=2; prev=A retained
        Assert.True(vault.WaitForPendingOps());

        // Current gen fails the stale slots; the fallback must rescue it.
        Assert.Equal(VaultState.Mounted, vault.State);
        Assert.Contains(logs,
            l => l.Contains("opened under the previous secret"));
        // Slots re-wrapped on adopt — the image now opens under gen 2.
        VaultHeader peeked = VaultVolume.PeekHeader(path)!;
        Assert.Equal((2u, 1u),
            (peeked.KeySlots[0].RotationGen, peeked.KeySlots[1].RotationGen));
        vault.KeyGone(); // release the service's handle before probing
        using (Open(path, genB)) { } // opens under the current secret alone
    }

    [Fact]
    public void Close_checkpoints_the_epoch()
    {
        // A mounted session flushes on teardown — the attested epoch must
        // follow so the same image doesn't read as rolled-back next open.
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        KeyConfig c = VaultConfig(path);
        using var vault = new VaultService(c, new TestMounter(), _ => { });
        vault.KeyVerified(secret.ToArray(), 1);
        Assert.True(vault.TryCreate(16, out string err), err);
        Assert.True(vault.WaitForPendingOps());
        Assert.Equal(1ul, c.VaultEpoch);

        // Dirty the live volume so KeyGone's dispose-flush bumps seq to 2.
        var live = (VaultVolume)typeof(VaultService)
            .GetField("_vol", System.Reflection.BindingFlags.NonPublic
                | System.Reflection.BindingFlags.Instance)!
            .GetValue(vault)!;
        live.CreateFile("\\late.txt", out _);
        vault.KeyGone();

        Assert.Equal(2ul, c.VaultEpoch); // checkpoint followed the late flush
    }

    // ---------------------------------------------------------- format v3

    [Fact]
    public void New_images_write_v3_with_empty_ext()
    {
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        using (VaultVolume.Create(path, 16, secret, 1)) { }
        VaultHeader h = VaultVolume.PeekHeader(path)!;
        Assert.Equal(VaultFormat.FormatVersion, h.Version); // 3
        Assert.False(h.TpmBound);
        Assert.False(h.HasRecovery);
        Assert.Equal(0u, h.RecIters);
        Assert.All(h.TpmBlob, b => Assert.Equal(0, b));
        Assert.All(h.RecBlob, b => Assert.Equal(0, b));
    }

    [Fact]
    public void Ext_region_is_checksum_covered()
    {
        // A flipped byte inside the ext region must fail the header — the
        // TPM blob can't be silently doctored to a different wrap.
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        using (VaultVolume.Create(path, 16, secret, 1)) { }
        byte[] page = File.ReadAllBytes(path)[..VaultFormat.HeaderSize];
        page[300] ^= 0xFF; // inside the tpmPepperBlob span
        Assert.Throws<VaultException>(() => VaultFormat.ReadHeader(page));
    }

    [Fact]
    public void V2_header_page_reads_as_unbound()
    {
        // Craft a v2-layout page from a real image's fields: version 2 +
        // the old @192 checksum. Reads must accept it as unbound.
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        using (VaultVolume.Create(path, 16, secret, 1)) { }
        byte[] page = File.ReadAllBytes(path)[..VaultFormat.HeaderSize];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(
            page.AsSpan(8), 2);
        SHA256.HashData(page.AsSpan(0, 192)).AsSpan(0, 8)
            .CopyTo(page.AsSpan(192));
        VaultHeader h = VaultFormat.ReadHeader(page);
        Assert.Equal(2u, h.Version);
        Assert.False(h.TpmBound);
        Assert.All(h.TpmBlob, b => Assert.Equal(0, b));
    }

    [Fact]
    public void Pepper_changes_the_kek()
    {
        byte[] secret = TestDisk.RandomSecret();
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] pepper = RandomNumberGenerator.GetBytes(32);
        byte[] plain = VaultFormat.DeriveKek(secret, salt);
        byte[] bound = VaultFormat.DeriveKek(secret, salt, pepper);
        Assert.NotEqual(plain, bound);
        // An empty pepper is byte-identical to the v2 derivation.
        Assert.Equal(plain, VaultFormat.DeriveKek(secret, salt, ReadOnlySpan<byte>.Empty));
    }

    // ------------------------------------------------------------ TPM seam

    /// <summary>XOR-fold fake: wraps to the 256B blob slot, unwraps back.</summary>
    private sealed class FakeTpm : IVaultTpm
    {
        public bool Available { get; set; } = true;
        public int DeleteCount;

        public byte[]? WrapPepper(byte[] pepper)
        {
            if (!Available) return null;
            byte[] blob = new byte[VaultFormat.TpmBlobLen];
            for (int i = 0; i < pepper.Length; i++)
                blob[i] = (byte)(pepper[i] ^ 0x5A);
            return blob;
        }

        public byte[]? UnwrapPepper(byte[] blob)
        {
            if (!Available || blob.Length != VaultFormat.TpmBlobLen)
                return null;
            byte[] pepper = new byte[VaultFormat.PepperLen];
            for (int i = 0; i < pepper.Length; i++)
                pepper[i] = (byte)(blob[i] ^ 0x5A);
            return pepper;
        }

        public void DeleteKey() => DeleteCount++;
    }

    private VaultService BoundVault(string path, byte[] secret,
        FakeTpm tpm, out KeyConfig config, List<string>? logs = null,
        string phrase = "passphrase-ok")
    {
        config = VaultConfig(path);
        var vault = new VaultService(config, new TestMounter(),
            logs != null ? logs.Add : (_ => { }), tpm: tpm);
        vault.KeyVerified(secret.ToArray(), 1);
        Assert.True(vault.TryCreate(16, out string cErr), cErr);
        Assert.True(vault.WaitForPendingOps());
        Assert.True(vault.BindTpm(phrase.AsSpan(), strict: false, out string bErr), bErr);
        Assert.True(vault.ImageTpmBound);
        return vault;
    }

    [Fact]
    public void Bind_requires_open_vault_and_phrase()
    {
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        var tpm = new FakeTpm();
        KeyConfig c = VaultConfig(path);
        using var vault = new VaultService(c, new TestMounter(), _ => { }, tpm: tpm);
        Assert.False(vault.BindTpm("passphrase-ok".AsSpan(), false, out string e1));
        Assert.Contains("unlock", e1);

        vault.KeyVerified(secret.ToArray(), 1);
        Assert.True(vault.TryCreate(16, out _));
        Assert.True(vault.WaitForPendingOps());
        Assert.False(vault.BindTpm("wrong-phrase".AsSpan(), false, out string e2));
        Assert.Contains("phrase", e2);
    }

    [Fact]
    public void Bound_image_needs_the_pepper()
    {
        // The security claim in miniature: the unpeppered KEK no longer
        // unwraps the slots — a copied image + cloned keyfile opens nowhere.
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        var tpm = new FakeTpm();
        using (var vault = BoundVault(path, secret, tpm, out _)) { }

        Assert.False(VaultVolume.TryOpen(path, KekFor(path, secret),
            out VaultVolume? vol, out VaultOpenError err, out _));
        Assert.Null(vol);
        Assert.Equal(VaultOpenError.Sealed, err); // unpeppered KEK — dead
    }

    [Fact]
    public void Tpm_absent_locks_not_corrupts()
    {
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        var tpm = new FakeTpm();
        using (var vault = BoundVault(path, secret, tpm, out KeyConfig c))
        {
            vault.KeyGone();
            vault.KeyVerified(secret.ToArray(), 1);
            Assert.True(vault.WaitForPendingOps());
            Assert.Equal(VaultState.Mounted, vault.State); // TPM unwraps

            tpm.Available = false; // TPM cleared / different machine
            vault.KeyGone();
            vault.KeyVerified(secret.ToArray(), 1);
            Assert.True(vault.WaitForPendingOps());
            Assert.Equal(VaultState.TpmLocked, vault.State);
        }
    }

    [Fact]
    public void Phrase_recovery_opens_then_rebinds()
    {
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        var tpm = new FakeTpm();
        using var vault = BoundVault(path, secret, tpm, out _);

        tpm.Available = false;
        vault.KeyGone();
        vault.KeyVerified(secret.ToArray(), 1);
        Assert.True(vault.WaitForPendingOps());
        Assert.Equal(VaultState.TpmLocked, vault.State);

        Assert.False(vault.UnlockWithPhrase("wrong-phrase".AsSpan(), out string e1));
        Assert.Contains("phrase", e1);
        Assert.True(vault.UnlockWithPhrase("passphrase-ok".AsSpan(), out string e2), e2);
        Assert.True(vault.WaitForPendingOps());
        Assert.Equal(VaultState.Mounted, vault.State); // opened without the TPM
        Assert.True(vault.NeedsRebind);                // banner state

        tpm.Available = true; // the TPM comes back — re-bind refreshes the blob
        Assert.True(vault.BindTpm(ReadOnlySpan<char>.Empty, false, out string e3), e3);
        Assert.False(vault.NeedsRebind);
    }

    [Fact]
    public void Unbind_returns_to_pepperless_open()
    {
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        var tpm = new FakeTpm();
        using var vault = BoundVault(path, secret, tpm, out _);

        Assert.True(vault.UnbindTpm(out string err), err);
        Assert.Equal(1, tpm.DeleteCount); // the TPM key died with the binding
        Assert.False(vault.ImageTpmBound);

        tpm.Available = false; // unbound opens need no TPM at all
        vault.KeyGone();
        vault.KeyVerified(secret.ToArray(), 1);
        Assert.True(vault.WaitForPendingOps());
        Assert.Equal(VaultState.Mounted, vault.State);
    }

    [Fact]
    public void Strict_bind_has_no_phrase_hatch()
    {
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        var tpm = new FakeTpm();
        KeyConfig c = VaultConfig(path);
        using var vault = new VaultService(c, new TestMounter(), _ => { }, tpm: tpm);
        vault.KeyVerified(secret.ToArray(), 1);
        Assert.True(vault.TryCreate(16, out _));
        Assert.True(vault.WaitForPendingOps());
        Assert.True(vault.BindTpm("passphrase-ok".AsSpan(), strict: true, out string err), err);

        VaultHeader h = VaultVolume.PeekHeader(path)!;
        Assert.True(h.TpmBound);
        Assert.Equal(0u, h.RecIters);
        Assert.All(h.RecBlob, b => Assert.Equal(0, b));

        tpm.Available = false;
        vault.KeyGone();
        vault.KeyVerified(secret.ToArray(), 1);
        Assert.True(vault.WaitForPendingOps());
        Assert.Equal(VaultState.TpmLocked, vault.State);
        Assert.False(vault.UnlockWithPhrase("passphrase-ok".AsSpan(), out string e2));
        Assert.Contains("strict", e2);
    }

    [Fact]
    public void Bound_slots_slide_under_the_pepper()
    {
        // A rotation on a bound vault re-wraps under PEPPERED KEKs — the
        // next open still needs the TPM.
        string path = Img();
        byte[] genA = TestDisk.RandomSecret();
        var tpm = new FakeTpm();
        byte[] genB = TestDisk.RandomSecret();
        using var vault = BoundVault(path, genA, tpm, out _);

        vault.KeyVerified(genB.ToArray(), 2); // rotation edge → peppered rewrap
        Assert.True(vault.WaitForPendingOps());
        Assert.Equal((2u, 1u), vault.SlotGens!.Value);

        vault.KeyGone();
        vault.KeyVerified(genB.ToArray(), 2);
        Assert.True(vault.WaitForPendingOps());
        Assert.Equal(VaultState.Mounted, vault.State);
    }

    [Fact]
    public void Rollback_fence_fires_on_bound_image()
    {
        // The epoch fence composes with binding: the pepper unwraps, the
        // open succeeds, THEN the seq compare rejects — no mount.
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        var tpm = new FakeTpm();
        KeyConfig c;
        using (var vault = BoundVault(path, secret, tpm, out c))
        {
            vault.KeyGone();
        }
        c.VaultEpoch = 10; // attested beyond the bound image's seq
        var mounter = new TestMounter();
        using var v2 = new VaultService(c, mounter, _ => { }, tpm: tpm);
        v2.KeyVerified(secret.ToArray(), 1);
        Assert.True(v2.WaitForPendingOps());
        Assert.Equal(VaultState.RolledBack, v2.State);
        Assert.Equal(0, mounter.MountCount);
    }

    [Fact]
    public void Keygone_drops_the_held_pepper()
    {
        // A recovered pepper dies with the session — reopening a bound
        // image after KeyGone needs the TPM (or the phrase) again.
        string path = Img();
        byte[] secret = TestDisk.RandomSecret();
        var tpm = new FakeTpm();
        using var vault = BoundVault(path, secret, tpm, out _);

        tpm.Available = false;
        vault.KeyGone();
        vault.KeyVerified(secret.ToArray(), 1);
        Assert.True(vault.WaitForPendingOps());
        Assert.Equal(VaultState.TpmLocked, vault.State);
        Assert.True(vault.UnlockWithPhrase("passphrase-ok".AsSpan(), out _));
        Assert.True(vault.WaitForPendingOps());
        Assert.Equal(VaultState.Mounted, vault.State);

        vault.KeyGone(); // pepper dropped — TPM still absent → locked again
        vault.KeyVerified(secret.ToArray(), 1);
        Assert.True(vault.WaitForPendingOps());
        Assert.Equal(VaultState.TpmLocked, vault.State);
    }
}
