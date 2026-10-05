using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CryptoKey;

/// <summary>Structural result for tree ops — crypto failures throw instead.</summary>
internal enum VaultResult
{
    Ok,
    NotFound,
    ParentMissing,
    NotEmpty,
    AlreadyExists,
    NotADirectory,
    IsADirectory,
    Full,
    InvalidName,
}

internal enum VaultOpenError
{
    None,
    NoImage,
    BadFormat,
    /// <summary>The KEK unwrapped no key slot — wrong-generation secret. Permanent.</summary>
    Sealed,
    /// <summary>Both manifest slots rejected — unrecoverable corruption.</summary>
    Corrupt,
}

/// <summary>One directory-tree entry. <see cref="Name"/> keeps creation casing.</summary>
internal sealed class VaultNode
{
    public string Name = "";
    public bool IsDir;
    public long Size;
    public DateTime CreatedUtc = DateTime.UtcNow;
    public DateTime ModifiedUtc = DateTime.UtcNow;
    public DateTime AccessedUtc = DateTime.UtcNow;
    public FileAttributes Attrs;
    /// <summary>Physical chunk id per logical 4 KiB block; -1 = sparse hole (reads as zeros).</summary>
    public List<int> Chunks = new();
}

/// <summary>
/// An open CKVAULT1 image: the directory tree + chunk allocator + write-through
/// chunked I/O over the sealed device. All public members serialize on an
/// internal lock — the Dokan adapter is called from many driver threads.
///
/// Chunks encrypt+write on every mutation (write-through); the manifest —
/// the tree + freelist — flushes on <see cref="Flush"/> (close/dismount).
/// A crash between the two loses only the manifest update: chunks the
/// persisted high-water never covered recycle naturally, and the open
/// path's freelist rebuild reconciles whatever the manifest did record.
/// </summary>
internal sealed class VaultVolume : IDisposable
{
    private readonly object _gate = new();
    private readonly FileStream _img;
    private readonly PinnedBuffer _volKey;
    private VaultHeader _header;
    private readonly SortedDictionary<string, VaultNode> _nodes =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly SortedSet<int> _free = new();
    private int _highWater;
    private ulong _manifestSeq;
    private bool _dirty;
    private bool _disposed;

    private VaultVolume(FileStream img, PinnedBuffer volKey, VaultHeader header)
    {
        _img = img;
        _volKey = volKey;
        _header = header;
    }

    public string ImagePath => _img.Name;
    public byte[] Salt => _header.Salt;
    public int ChunkCount => (int)_header.ChunkCount;

    /// <summary>
    /// The authenticated manifest sequence — monotonic, sealed inside the
    /// GCM manifest blob. The service attests the highest seen so a
    /// whole-image rollback is detectable. In-memory only — safe to read
    /// after Dispose (the final flush has already landed).
    /// </summary>
    public ulong ManifestSeq { get { lock (_gate) return _manifestSeq; } }

    /// <summary>Chunks the open-time freelist rebuild reclaimed (0 on a clean open).</summary>
    internal int LastHealOrphans { get; private set; }

    // ------------------------------------------------------------ create/open

    /// <summary>
    /// Read just the header — no unwrapping. Gives callers the headerSalt for
    /// KEK derivation and the slot generations for reporting.
    /// </summary>
    public static VaultHeader? PeekHeader(string path)
        => PeekHeader(path, out _);

    /// <summary>
    /// Peek with diagnosis: NoImage when the file can't be opened (absent or
    /// transiently locked), BadFormat when both header pages reject — the
    /// distinction a caller needs to tell "retry later" from "corrupt".
    /// </summary>
    public static VaultHeader? PeekHeader(string path, out VaultOpenError error)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite);
            VaultHeader? h = ReadHeaderEither(fs);
            error = h == null ? VaultOpenError.BadFormat : VaultOpenError.None;
            return h;
        }
        catch (FileNotFoundException) { error = VaultOpenError.NoImage; return null; }
        catch (DirectoryNotFoundException) { error = VaultOpenError.NoImage; return null; }
        catch (Exception)
        {
            error = VaultOpenError.Corrupt; // sharing/IO — treated as transient by callers
            return null;
        }
    }

    /// <summary>
    /// Primary header page, falling back to the shadow copy — a torn
    /// WriteHeader leaves one intact page. Null only when both reject.
    /// </summary>
    private static VaultHeader? ReadHeaderEither(FileStream fs)
    {
        foreach (long at in new[] { 0L, VaultFormat.ShadowBase })
        {
            byte[] page = new byte[VaultFormat.HeaderSize];
            fs.Position = at;
            if (fs.Read(page, 0, page.Length) < page.Length)
                continue;
            try
            {
                return VaultFormat.ReadHeader(page);
            }
            catch (VaultException)
            {
                // torn/garbage — try the other copy
            }
        }
        return null;
    }

    /// <summary>
    /// Create a fresh image at <paramref name="path"/>: random volume key
    /// wrapped under a KEK derived from <paramref name="secret"/> in both
    /// slots, empty root dir. Total on-disk size = <paramref name="sizeMb"/>
    /// MiB; the manifest region (8 MiB + header) comes out of that budget.
    /// </summary>
    public static VaultVolume Create(string path, int sizeMb, byte[] secret, uint gen)
    {
        long bytes = (long)sizeMb * 1024 * 1024;
        long regionBytes = bytes - VaultFormat.DataOffset;
        if (regionBytes < VaultFormat.ChunkSize * 4)
            throw new VaultException($"vault too small — {sizeMb} MB leaves no chunk region");

        byte[] salt = RandomNumberGenerator.GetBytes(VaultFormat.SaltLen);
        byte[] kek = VaultFormat.DeriveKek(secret, salt);
        byte[] vk = RandomNumberGenerator.GetBytes(VaultFormat.VolKeyLen);
        var volKey = new PinnedBuffer(vk);
        CryptographicOperations.ZeroMemory(vk);
        try
        {
            VaultHeader header;
            try
            {
                header = new VaultHeader(
                    VaultFormat.FormatVersion, 0,
                    salt,
                    new[]
                    {
                        VaultFormat.WrapVolumeKey(kek, volKey.Bytes, gen, 0),
                        VaultFormat.WrapVolumeKey(kek, volKey.Bytes, gen, 1),
                    },
                    0, 0,
                    (uint)(regionBytes / VaultFormat.ChunkSize),
                    VaultFormat.DataOffset);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(kek); // KEK is derived on demand — not held
            }

            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
            // FileShare.Read (not None): read-only peeks may coexist with us.
            var fs = new FileStream(path, FileMode.Create, FileAccess.ReadWrite, FileShare.Read);
            fs.SetLength(VaultFormat.DataOffset + (long)header.ChunkCount * VaultFormat.ChunkSize);
            var vol = new VaultVolume(fs, volKey, header);
            vol._nodes["\\"] = new VaultNode
            {
                Name = "", IsDir = true,
                Attrs = FileAttributes.Directory | FileAttributes.Hidden,
            };
            try
            {
                vol.Flush(); // seq 1 → slot 1... first flush writes slot (seq&1)
            }
            catch
            {
                vol.Dispose();
                throw;
            }
            return vol;
        }
        catch
        {
            volKey.Dispose();
            // A half-created image must not squat on the path — the next
            // TryCreate checks ImageExists and would refuse forever.
            try { File.Delete(path); } catch (Exception) { }
            throw;
        }
    }

    /// <summary>
    /// Open an image under a KEK: unwrap either key slot, then load the
    /// newest manifest slot that decrypts (torn writes fall back to the
    /// older epoch). <paramref name="openedSlot"/> reports which key slot
    /// matched, for the re-wrap bookkeeping.
    /// </summary>
    public static bool TryOpen(string path, byte[] kek,
        out VaultVolume? volume, out VaultOpenError error, out int openedSlot)
    {
        volume = null;
        openedSlot = -1;
        error = VaultOpenError.None;
        FileStream? fs = null;
        PinnedBuffer? volKey = null;
        try
        {
            // FileShare.Read: read-only peeks (header/status probes from a
            // second process) are allowed; no second writer can ever open.
            fs = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.Read);
            VaultHeader? header = ReadHeaderEither(fs);
            if (header == null)
            {
                error = VaultOpenError.BadFormat;
                return false;
            }

            for (int i = 0; i < VaultFormat.KeySlots; i++)
            {
                byte[]? vk = VaultFormat.UnwrapVolumeKey(kek, header.KeySlots[i], i);
                if (vk != null)
                {
                    volKey = new PinnedBuffer(vk);
                    CryptographicOperations.ZeroMemory(vk); // pinned copy owns it now
                    openedSlot = i;
                    break;
                }
            }
            if (volKey == null)
            {
                error = VaultOpenError.Sealed;
                return false;
            }

            var vol = new VaultVolume(fs, volKey, header);
            vol.LoadManifest(volKey.Bytes); // throws VaultIntegrity on both-slots-dead
            volume = vol;
            fs = null;
            volKey = null;
            return true;
        }
        catch (FileNotFoundException) { error = VaultOpenError.NoImage; return false; }
        catch (DirectoryNotFoundException) { error = VaultOpenError.NoImage; return false; }
        catch (VaultIntegrityException) { error = VaultOpenError.Corrupt; return false; }
        catch (IOException) { error = VaultOpenError.Corrupt; return false; }
        finally
        {
            fs?.Dispose();
            volKey?.Dispose();
        }
    }

    /// <summary>Rewrite both key slots (gen slide on rotation). Slot0 = newest.</summary>
    public void ReWrapKeys(byte[] kekCurrent, byte[]? kekPrevious, uint genCurrent, uint genPrevious)
    {
        lock (_gate)
        {
            _header.KeySlots[0] =
                VaultFormat.WrapVolumeKey(kekCurrent, _volKey.Bytes, genCurrent, 0);
            _header.KeySlots[1] = kekPrevious != null
                ? VaultFormat.WrapVolumeKey(kekPrevious, _volKey.Bytes, genPrevious, 1)
                : VaultFormat.WrapVolumeKey(kekCurrent, _volKey.Bytes, genCurrent, 1);
            WriteHeader();
        }
    }

    /// <summary>Which generation each key slot was last wrapped under — for reporting.</summary>
    public (uint A, uint B) SlotGens
    {
        get { lock (_gate) return (_header.KeySlots[0].RotationGen, _header.KeySlots[1].RotationGen); }
    }

    // --------------------------------------------------------------- path API

    /// <summary>Canonical form: "\"-rooted, resolved "."/"..", collapsed separators.</summary>
    public static string Normalize(string path)
    {
        var parts = new List<string>();
        foreach (string seg in path.Split('\\', '/'))
        {
            if (seg.Length == 0 || seg == ".")
                continue;
            if (seg == "..")
            {
                if (parts.Count > 0)
                    parts.RemoveAt(parts.Count - 1);
                continue;
            }
            parts.Add(seg);
        }
        return "\\" + string.Join("\\", parts);
    }

    private static bool ValidName(string name)
        => name.Length > 0 && name.Length <= 255
           && name.IndexOfAny(new[] { '<', '>', ':', '"', '|', '?', '*' }) < 0
           && name[^1] != '.' && name[^1] != ' ';

    private static string ParentOf(string path)
    {
        int i = path.LastIndexOf('\\');
        return i <= 0 ? "\\" : path[..i];
    }

    private static string LeafOf(string path)
    {
        int i = path.LastIndexOf('\\');
        return i < 0 ? path : path[(i + 1)..];
    }

    public bool TryGet(string path, out VaultNode node)
    {
        lock (_gate)
            return _nodes.TryGetValue(Normalize(path), out node!);
    }

    /// <summary>Immediate children of <paramref name="dirPath"/>.</summary>
    public List<VaultNode> List(string dirPath)
    {
        lock (_gate)
        {
            string dir = Normalize(dirPath);
            if (!_nodes.TryGetValue(dir, out VaultNode? parent) || !parent.IsDir)
                return new List<VaultNode>();
            string prefix = dir == "\\" ? "\\" : dir + "\\";
            var result = new List<VaultNode>();
            foreach ((string p, VaultNode n) in _nodes)
            {
                if (p.Length > prefix.Length
                    && p.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
                    && p.IndexOf('\\', prefix.Length) < 0)
                    result.Add(n);
            }
            return result;
        }
    }

    public VaultResult CreateFile(string path, out VaultNode? node)
        => Create(path, isDir: false, out node);

    public VaultResult CreateDir(string path, out VaultNode? node)
        => Create(path, isDir: true, out node);

    private VaultResult Create(string path, bool isDir, out VaultNode? node)
    {
        lock (_gate)
        {
            node = null;
            string p = Normalize(path);
            if (p == "\\")
                return VaultResult.InvalidName;
            string leaf = LeafOf(p);
            if (!ValidName(leaf))
                return VaultResult.InvalidName;
            if (!_nodes.TryGetValue(ParentOf(p), out VaultNode? parent))
                return VaultResult.ParentMissing;
            if (!parent.IsDir)
                return VaultResult.NotADirectory;
            if (_nodes.ContainsKey(p))
                return VaultResult.AlreadyExists;
            var now = DateTime.UtcNow;
            node = new VaultNode
            {
                Name = leaf,
                IsDir = isDir,
                CreatedUtc = now,
                ModifiedUtc = now,
                AccessedUtc = now,
                Attrs = isDir ? FileAttributes.Directory : FileAttributes.Archive,
            };
            _nodes[p] = node;
            _dirty = true;
            return VaultResult.Ok;
        }
    }

    /// <summary>Delete a file or empty directory. Frees the file's chunks to the freelist.</summary>
    public VaultResult Delete(string path)
    {
        lock (_gate)
        {
            string p = Normalize(path);
            if (p == "\\" || !_nodes.TryGetValue(p, out VaultNode? node))
                return VaultResult.NotFound;
            if (node.IsDir && List(p).Count > 0)
                return VaultResult.NotEmpty;
            foreach (int chunk in node.Chunks)
                if (chunk >= 0)
                    _free.Add(chunk);
            _nodes.Remove(p);
            _dirty = true;
            return VaultResult.Ok;
        }
    }

    /// <summary>Rename/move — directory moves carry the whole subtree.</summary>
    public VaultResult Move(string from, string to, bool replace)
    {
        lock (_gate)
        {
            string src = Normalize(from), dst = Normalize(to);
            if (src == "\\" || !_nodes.TryGetValue(src, out VaultNode? node))
                return VaultResult.NotFound;
            string dstLeaf = LeafOf(dst);
            if (!ValidName(dstLeaf))
                return VaultResult.InvalidName;
            if (!_nodes.TryGetValue(ParentOf(dst), out VaultNode? dstParent))
                return VaultResult.ParentMissing;
            if (!dstParent.IsDir)
                return VaultResult.NotADirectory;
            if (dst.Equals(src, StringComparison.OrdinalIgnoreCase))
            {
                // Case-only rename — same key, new display casing.
                node.Name = dstLeaf;
                _dirty = true;
                return VaultResult.Ok;
            }
            if (_nodes.ContainsKey(dst))
            {
                if (!replace)
                    return VaultResult.AlreadyExists;
                VaultResult del = Delete(dst);
                if (del != VaultResult.Ok)
                    return del;
            }
            // A dir can't move into its own subtree.
            if (node.IsDir && (dst.Equals(src, StringComparison.OrdinalIgnoreCase)
                || dst.StartsWith(src + "\\", StringComparison.OrdinalIgnoreCase)))
                return VaultResult.InvalidName;

            if (node.IsDir)
            {
                string oldPrefix = src + "\\";
                var moves = _nodes
                    .Where(kv => kv.Key.StartsWith(oldPrefix, StringComparison.OrdinalIgnoreCase))
                    .Select(kv => (oldKey: kv.Key, newKey: dst + kv.Key[oldPrefix.Length..],
                                   node: kv.Value))
                    .ToList();
                foreach ((string ok, string nk, VaultNode sub) in moves)
                {
                    _nodes.Remove(ok);
                    _nodes[nk] = sub;
                }
            }
            _nodes.Remove(src);
            node.Name = dstLeaf;
            node.ModifiedUtc = DateTime.UtcNow;
            _nodes[dst] = node;
            _dirty = true;
            return VaultResult.Ok;
        }
    }

    public VaultResult SetTimes(string path, DateTime? created, DateTime? accessed, DateTime? written)
    {
        lock (_gate)
        {
            if (!_nodes.TryGetValue(Normalize(path), out VaultNode? node))
                return VaultResult.NotFound;
            if (created is DateTime c) node.CreatedUtc = c;
            if (accessed is DateTime a) node.AccessedUtc = a;
            if (written is DateTime w) node.ModifiedUtc = w;
            _dirty = true;
            return VaultResult.Ok;
        }
    }

    public VaultResult SetAttributes(string path, FileAttributes attrs)
    {
        lock (_gate)
        {
            if (!_nodes.TryGetValue(Normalize(path), out VaultNode? node))
                return VaultResult.NotFound;
            node.Attrs = (attrs & ~FileAttributes.Directory)
                | (node.IsDir ? FileAttributes.Directory : 0);
            _dirty = true;
            return VaultResult.Ok;
        }
    }

    // ---------------------------------------------------------------- file IO

    /// <summary>Read <paramref name="dst"/> at <paramref name="offset"/>; returns bytes read.</summary>
    public int Read(string path, long offset, Span<byte> dst)
    {
        lock (_gate)
        {
            if (!_nodes.TryGetValue(Normalize(path), out VaultNode? node) || node.IsDir)
                throw new VaultException("read on a missing or directory node");
            if (offset >= node.Size || dst.Length == 0)
                return 0;
            int want = (int)Math.Min(dst.Length, node.Size - offset);
            byte[] chunkBuf = new byte[VaultFormat.ChunkPayload];
            int done = 0;
            while (done < want)
            {
                int idx = (int)((offset + done) / VaultFormat.ChunkPayload);
                int inChunk = (int)((offset + done) % VaultFormat.ChunkPayload);
                int take = Math.Min(VaultFormat.ChunkPayload - inChunk, want - done);
                if (idx < node.Chunks.Count && node.Chunks[idx] >= 0)
                {
                    ReadChunk(node.Chunks[idx], chunkBuf);
                    chunkBuf.AsSpan(inChunk, take).CopyTo(dst[done..]);
                }
                else
                {
                    dst.Slice(done, take).Clear(); // sparse hole / tail — zeros
                }
                done += take;
            }
            CryptographicOperations.ZeroMemory(chunkBuf);
            node.AccessedUtc = DateTime.UtcNow;
            return done;
        }
    }

    /// <summary>Write <paramref name="src"/> at <paramref name="offset"/>; extends the file as needed.</summary>
    public VaultResult Write(string path, long offset, ReadOnlySpan<byte> src, out int written)
    {
        lock (_gate)
        {
            written = 0;
            if (!_nodes.TryGetValue(Normalize(path), out VaultNode? node) || node.IsDir)
                return VaultResult.NotFound;
            if (src.Length == 0)
                return VaultResult.Ok;

            byte[] chunkBuf = new byte[VaultFormat.ChunkPayload];
            int done = 0;
            var res = VaultResult.Ok;
            try
            {
                while (done < src.Length)
                {
                    int idx = (int)((offset + done) / VaultFormat.ChunkPayload);
                    int inChunk = (int)((offset + done) % VaultFormat.ChunkPayload);
                    int take = Math.Min(VaultFormat.ChunkPayload - inChunk, src.Length - done);

                    // Grow the chunk table to cover idx (holes allowed — sparse).
                    while (node.Chunks.Count <= idx)
                        node.Chunks.Add(-1);

                    bool full = take == VaultFormat.ChunkPayload;
                    int id = node.Chunks[idx];
                    if (id < 0)
                    {
                        if (!Alloc(out id))
                        {
                            res = VaultResult.Full;
                            break; // fall through — the landed bytes still count
                        }
                        node.Chunks[idx] = id;
                        chunkBuf.AsSpan().Clear();
                        if (!full && inChunk == 0 && node.Size > offset + done)
                        { /* hole mid-file — already zeros */ }
                    }
                    else if (!full)
                    {
                        ReadChunk(id, chunkBuf); // RMW — throws on tag failure
                    }
                    src.Slice(done, take).CopyTo(chunkBuf.AsSpan(inChunk));
                    WriteChunk(id, chunkBuf);
                    done += take;
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(chunkBuf);
            }
            written = done;
            long end = offset + done;
            if (end > node.Size)
                node.Size = end;
            node.ModifiedUtc = node.AccessedUtc = DateTime.UtcNow;
            _dirty = true;
            return res;
        }
    }

    /// <summary>Resize: shrink frees tail chunks, grow leaves sparse holes.</summary>
    public VaultResult SetLength(string path, long length)
    {
        lock (_gate)
        {
            if (!_nodes.TryGetValue(Normalize(path), out VaultNode? node) || node.IsDir)
                return VaultResult.NotFound;
            if (length < 0)
                return VaultResult.InvalidName;
            if (length < node.Size)
            {
                // Chunks.Count can be *below* keepChunks when a sparse grow
                // preceded this shrink (grown files carry an empty table).
                int keep = (int)Math.Min(
                    (length + VaultFormat.ChunkPayload - 1) / VaultFormat.ChunkPayload,
                    node.Chunks.Count);
                for (int i = keep; i < node.Chunks.Count; i++)
                    if (node.Chunks[i] >= 0)
                        _free.Add(node.Chunks[i]);
                node.Chunks.RemoveRange(keep, node.Chunks.Count - keep);
                int tailIdx = (int)(length / VaultFormat.ChunkPayload);
                if (length % VaultFormat.ChunkPayload != 0
                    && tailIdx < node.Chunks.Count && node.Chunks[tailIdx] >= 0)
                {
                    // Zero the tail of the straddling chunk so stale bytes can't leak.
                    byte[] buf = new byte[VaultFormat.ChunkPayload];
                    ReadChunk(node.Chunks[tailIdx], buf);
                    buf.AsSpan((int)(length % VaultFormat.ChunkPayload)).Clear();
                    WriteChunk(node.Chunks[tailIdx], buf);
                    CryptographicOperations.ZeroMemory(buf);
                }
            }
            node.Size = length;
            node.ModifiedUtc = DateTime.UtcNow;
            _dirty = true;
            return VaultResult.Ok;
        }
    }

    /// <summary>used / total payload bytes — the UI usage meter.</summary>
    public (long Used, long Total) GetUsage()
    {
        lock (_gate)
            return ((long)(_highWater - _free.Count) * VaultFormat.ChunkPayload,
                    (long)_header.ChunkCount * VaultFormat.ChunkPayload);
    }

    // ------------------------------------------------------------- chunk I/O

    private bool Alloc(out int id)
    {
        if (_free.Count > 0)
        {
            id = _free.Min;
            _free.Remove(id);
            return true;
        }
        if (_highWater >= _header.ChunkCount)
        {
            id = -1;
            return false;
        }
        id = _highWater++;
        return true;
    }

    private void ReadChunk(int id, Span<byte> dst4096)
    {
        byte[] frame = new byte[VaultFormat.ChunkSize];
        _img.Position = VaultFormat.ChunkOffset(_header.ChunkRegionBase, id);
        if (_img.Read(frame, 0, frame.Length) < frame.Length)
            throw new VaultIntegrityException($"short read on chunk {id}");
        if (!VaultFormat.TryDecryptChunk(_volKey.Bytes, id, frame, dst4096))
            throw new VaultIntegrityException($"chunk {id} tag rejected — tampered or corrupt");
    }

    private void WriteChunk(int id, ReadOnlySpan<byte> src4096)
    {
        byte[] frame = VaultFormat.EncryptChunk(_volKey.Bytes, id, src4096);
        _img.Position = VaultFormat.ChunkOffset(_header.ChunkRegionBase, id);
        _img.Write(frame, 0, frame.Length);
    }

    // --------------------------------------------------------------- manifest

    /// <summary>Seal the tree+freelist into the next manifest slot; updates the header.</summary>
    public void Flush()
    {
        lock (_gate)
        {
            if (_disposed)
                return;
            _manifestSeq++;
            int slot = (int)(_manifestSeq & 1);
            byte[] blob = VaultFormat.SealManifest(
                _volKey.Bytes, slot, _manifestSeq, SerializeManifest());
            _img.Position = VaultFormat.ManifestBase + (long)slot * VaultFormat.ManifestSlotSize;
            _img.Write(blob, 0, blob.Length);
            if (slot == 0) _header.ManifestSeq0 = _manifestSeq;
            else _header.ManifestSeq1 = _manifestSeq;
            WriteHeader();
            _img.Flush(true);
            _dirty = false;
        }
    }

    private void WriteHeader()
    {
        // Shadow first, primary last: a torn flush leaves the primary —
        // the page readers prefer — intact.
        byte[] page = VaultFormat.WriteHeader(_header);
        _img.Position = VaultFormat.ShadowBase;
        _img.Write(page, 0, page.Length);
        _img.Position = 0;
        _img.Write(page, 0, page.Length);
        _img.Flush(true);
    }

    private void LoadManifest(byte[] volKey)
    {
        // Newest decrypting slot wins; the other is the torn-write fallback.
        // The slot's own authenticated seq is authoritative — the header's
        // manifestSeq fields are write-only bookkeeping.
        byte[]? best = null;
        ulong bestSeq = 0;
        for (int i = 0; i < VaultFormat.ManifestSlots; i++)
        {
            byte[] head = new byte[VaultFormat.ManifestHeadLen];
            _img.Position = VaultFormat.ManifestBase + (long)i * VaultFormat.ManifestSlotSize;
            if (_img.Read(head, 0, head.Length) < head.Length)
                continue;
            uint plainLen = head.Length >= VaultFormat.ManifestHeadLen
                && BitConverter.ToUInt32(head, 0) == VaultFormat.ManifestMagic
                ? BitConverter.ToUInt32(head, 12)
                : 0;
            if (plainLen == 0 || plainLen > VaultFormat.MaxManifestPayload)
                continue;
            byte[] blob = new byte[VaultFormat.ManifestHeadLen + plainLen];
            head.CopyTo(blob, 0);
            _img.Position = VaultFormat.ManifestBase + (long)i * VaultFormat.ManifestSlotSize;
            if (_img.Read(blob, 0, blob.Length) < blob.Length)
                continue;
            byte[]? plain = VaultFormat.TryOpenManifest(volKey, i, blob, out ulong seq);
            if (plain != null && seq >= bestSeq)
            {
                best?.AsSpan().Clear();
                best = plain;
                bestSeq = seq;
            }
            else if (plain != null)
            {
                plain.AsSpan().Clear();
            }
        }
        if (best == null)
            throw new VaultIntegrityException("both manifest slots rejected — image is corrupt");
        _manifestSeq = bestSeq;
        try
        {
            DeserializeManifest(best);
        }
        catch (JsonException ex)
        {
            throw new VaultIntegrityException($"manifest payload corrupt: {ex.Message}");
        }
        finally
        {
            best.AsSpan().Clear();
        }
    }

    // Manifest JSON — short names keep the 4 MiB slot roomy. Paths are the
    // keys: encrypted under the volume key, so filenames stay confidential.
    private sealed class ManifestDto
    {
        [JsonPropertyName("v")] public int V { get; set; } = 1;
        [JsonPropertyName("hw")] public int HighWater { get; set; }
        [JsonPropertyName("free")] public List<int> Free { get; set; } = new();
        [JsonPropertyName("nodes")] public List<NodeDto> Nodes { get; set; } = new();
    }

    private sealed class NodeDto
    {
        [JsonPropertyName("p")] public string P { get; set; } = "";
        [JsonPropertyName("n")] public string N { get; set; } = "";
        [JsonPropertyName("d")] public bool D { get; set; }
        [JsonPropertyName("s")] public long S { get; set; }
        [JsonPropertyName("c")] public long C { get; set; }
        [JsonPropertyName("w")] public long W { get; set; }
        [JsonPropertyName("a")] public long A { get; set; }
        [JsonPropertyName("t")] public int T { get; set; }
        [JsonPropertyName("k")] public List<int> K { get; set; } = new();
    }

    private byte[] SerializeManifest()
    {
        var dto = new ManifestDto
        {
            HighWater = _highWater,
            Free = _free.ToList(),
            Nodes = _nodes.Select(kv => new NodeDto
            {
                P = kv.Key, N = kv.Value.Name, D = kv.Value.IsDir, S = kv.Value.Size,
                C = kv.Value.CreatedUtc.Ticks, W = kv.Value.ModifiedUtc.Ticks,
                A = kv.Value.AccessedUtc.Ticks, T = (int)kv.Value.Attrs, K = kv.Value.Chunks,
            }).ToList(),
        };
        return JsonSerializer.SerializeToUtf8Bytes(dto);
    }

    private void DeserializeManifest(byte[] plain)
    {
        ManifestDto dto = JsonSerializer.Deserialize<ManifestDto>(plain)
            ?? throw new VaultIntegrityException("empty manifest payload");
        _nodes.Clear();
        _free.Clear();
        foreach (NodeDto n in dto.Nodes)
        {
            _nodes[Normalize(n.P)] = new VaultNode
            {
                Name = n.N,
                IsDir = n.D,
                Size = n.S,
                CreatedUtc = new DateTime(n.C, DateTimeKind.Utc),
                ModifiedUtc = new DateTime(n.W, DateTimeKind.Utc),
                AccessedUtc = new DateTime(n.A, DateTimeKind.Utc),
                Attrs = (FileAttributes)n.T,
                Chunks = n.K,
            };
        }
        if (!_nodes.ContainsKey("\\"))
            _nodes["\\"] = new VaultNode
                { IsDir = true, Attrs = FileAttributes.Directory | FileAttributes.Hidden };
        foreach (int id in dto.Free)
            _free.Add(id);
        _highWater = dto.HighWater;
        RebuildFreeList(); // owns _dirty — every change class must persist
    }

    /// <summary>
    /// Reconcile the persisted freelist against the node tree at open:
    /// unreferenced chunks the manifest's own high-water accounts for are
    /// reclaimed, garbage free entries clamp, and a chunk that is both
    /// referenced and free keeps its reference (data wins). Structural
    /// lies stay loud: an out-of-range or doubly-referenced chunk is real
    /// corruption, not an orphan. In-memory scan only — no chunk I/O.
    /// </summary>
    private void RebuildFreeList()
    {
        LastHealOrphans = 0;
        var referenced = new HashSet<int>();
        foreach (VaultNode n in _nodes.Values)
        {
            foreach (int c in n.Chunks)
            {
                if (c < 0)
                    continue; // sparse hole — not a reference
                if (c >= ChunkCount)
                    throw new VaultIntegrityException(
                        $"manifest references chunk {c} out of range");
                if (!referenced.Add(c))
                    throw new VaultIntegrityException(
                        $"chunk {c} referenced twice — corrupt manifest");
            }
        }
        if (_highWater < 0 || _highWater > ChunkCount)
            throw new VaultIntegrityException(
                $"manifest high-water {_highWater} out of range");

        // Garbage free entries (negative or past the high-water) get clamped;
        // every unreferenced allocated chunk returns to the freelist.
        int clamped = _free.RemoveWhere(id => id < 0 || id >= _highWater);
        for (int i = 0; i < _highWater; i++)
            if (!referenced.Contains(i) && _free.Add(i))
                LastHealOrphans++;
        // A chunk listed as both referenced and free is a conflict — the
        // reference wins (keep the data), the free entry drops.
        int conflicts = _free.RemoveWhere(referenced.Contains);
        LastHealOrphans += conflicts;
        // All three change classes dirty the manifest — a clamp-only heal
        // that doesn't persist just re-runs silently on every open.
        _dirty = clamped > 0 || LastHealOrphans > 0;
    }

    /// <summary>Sum of every node's chunk list — structural self-check for tests.</summary>
    internal (int Allocated, int HighWater, int Freed) DebugChunkStats()
    {
        lock (_gate)
            return (_nodes.Values.Sum(n => n.Chunks.Count(c => c >= 0)),
                    _highWater, _free.Count);
    }

    /// <summary>
    /// Test hook: die mid-session — release the image handle and key
    /// WITHOUT the dirty-flush, exactly like a process crash after a
    /// write-through chunk landed but before the manifest sealed.
    /// </summary>
    internal void SimulateCrash()
    {
        lock (_gate)
        {
            _disposed = true;
            _volKey.Dispose();
            _img.Dispose();
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
                return;
            try { if (_dirty) Flush(); }
            catch (Exception) { }
            _disposed = true;
            _volKey.Dispose();
            _img.Dispose();
        }
    }
}

/// <summary>
/// A pinned managed buffer for key material — GC can't move it, and Dispose
/// zeroes + frees it. KEKs and the volume key live in these.
/// </summary>
internal sealed class PinnedBuffer : IDisposable
{
    private System.Runtime.InteropServices.GCHandle _pin;
    private readonly byte[] _bytes;

    /// <summary>Copies <paramref name="bytes"/> into the pinned array — the caller's
    /// buffer stays its own (and may be zeroed independently).</summary>
    public PinnedBuffer(byte[] bytes)
    {
        _bytes = new byte[bytes.Length];
        bytes.CopyTo(_bytes, 0);
        _pin = System.Runtime.InteropServices.GCHandle.Alloc(
            _bytes, System.Runtime.InteropServices.GCHandleType.Pinned);
    }

    public byte[] Bytes => _bytes;

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(_bytes);
        if (_pin.IsAllocated)
            _pin.Free();
    }
}
