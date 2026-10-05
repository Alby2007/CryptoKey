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
        Assert.Equal(VaultState.Mounted, vault.State); // auto-mount on, driver present (test fake)

        vault.KeyGone();
        Assert.Equal(VaultState.Sealed, vault.State); // image exists, secret dropped

        vault.KeyVerified(secret.ToArray(), 1);
        Assert.Equal(VaultState.Mounted, vault.State); // unsealed + re-mounted
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

        public IVaultMount? Mount(VaultVolume volume, string mountPoint, out string? error)
        {
            error = null;
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
        Assert.Equal(VaultState.NeedsDriver, vault.State); // unsealed but no driver
        Assert.False(vault.DriverPresent);
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

        // Rotation edge: the drive now presents gen B — service slides slots.
        byte[] genB = TestDisk.RandomSecret();
        vault.KeyVerified(genB.ToArray(), 2);

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
        byte[] genC = TestDisk.RandomSecret();
        vault.KeyVerified(genC.ToArray(), 3);
        vault.KeyGone();
        using (Open(path, genC)) { }
        using (Open(path, genB)) { }
        byte[] kekA = KekFor(path, genA);
        Assert.False(VaultVolume.TryOpen(path, kekA, out _, out _, out _));
        CryptographicOperations.ZeroMemory(kekA);
    }
}
