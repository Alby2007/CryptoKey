using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CryptoKey;

/// <summary>
/// The CKVAULT1 on-disk format — header, key slots, manifest slots, chunk
/// codec. Pure format layer: no directory tree, no allocator, no state.
///
/// <code>
/// header page (4 KiB):
///   0   magic "CKVAULT\x01"        8B
///   8   formatVersion u32
///   12  flags u32
///   16  headerSalt 16B
///   32  keySlot[0] 64B  { rotationGen u32 | nonce 12B | wrappedVolKey 48B }
///   96  keySlot[1] 64B
///   160 manifestSeq[0] u64
///   168 manifestSeq[1] u64
///   176 chunkCount u32
///   180 chunkRegionBase u64
///
/// manifest slot i at HeaderSize + i*ManifestSlotSize (4 MiB each):
///   0   slotMagic "CKVM" u32 | seq u64 | plainLen u32
///   16  nonce 12B | tag 16B
///   44  ciphertext[plainLen]
///
/// chunk i at chunkRegionBase + i*ChunkSize (4124B):
///   nonce 12B | tag 16B | ciphertext 4096B
/// </code>
///
/// Two-layer keys: a random 256-bit volume key seals every chunk + the
/// manifest; the enrolled drive's device secret wraps the volume key via
/// KEK = HMAC-SHA256(secret, "CryptoKeyVaultKEK" ‖ headerSalt). Two key
/// slots mirror the keyfile's current/previous ratchet window.
/// </summary>
internal static class VaultFormat
{
    internal static readonly byte[] HeaderMagic = "CKVAULT\x01"u8.ToArray();

    internal const uint FormatVersion = 1;
    internal const uint ManifestMagic = 0x4D564B43; // "CKVM" little-endian
    internal const uint ManifestFormat = 1;

    internal const int HeaderSize = 4096;
    internal const int SaltLen = 16;
    internal const int KeySlotLen = 64;
    internal const int KeySlots = 2;
    internal const int NonceLen = 12;
    internal const int TagLen = 16;
    internal const int VolKeyLen = 32;
    internal const int WrappedKeyLen = VolKeyLen + TagLen; // 48

    internal const int ChunkPayload = 4096;
    internal const int ChunkSize = NonceLen + TagLen + ChunkPayload; // 4124

    internal const int ManifestSlotSize = 4 * 1024 * 1024;
    internal const int ManifestSlots = 2;
    internal const int ManifestHeadLen = 44; // magic|seq|plainLen|nonce|tag
    internal const int MaxManifestPayload = ManifestSlotSize - ManifestHeadLen;

    internal const long ManifestBase = HeaderSize;
    internal const long DataOffset = HeaderSize + ManifestSlots * (long)ManifestSlotSize;

    // Header field offsets.
    private const int OffVersion = 8;
    private const int OffFlags = 12;
    private const int OffSalt = 16;
    private const int OffKeySlot = 32;
    private const int OffManifestSeq = OffKeySlot + KeySlots * KeySlotLen; // 160
    private const int OffChunkCount = OffManifestSeq + ManifestSlots * 8;  // 176
    private const int OffChunkBase = OffChunkCount + 8;                    // 184

    // Key slot field offsets (within a 64B slot).
    private const int SlotGenOff = 0;
    private const int SlotNonceOff = 4;
    private const int SlotWrapOff = 16;

    private static readonly byte[] KekLabel = "CryptoKeyVaultKEK"u8.ToArray();
    private static readonly byte[] SlotAadLabel = "CKVKEYSLOT"u8.ToArray();
    private static readonly byte[] ManifestAadLabel = "CKVMANIFEST"u8.ToArray();
    private static readonly byte[] ChunkAadLabel = "CKVCHUNK"u8.ToArray();

    /// <summary>Key-wrapping key for a verified device secret + this image's salt.</summary>
    internal static byte[] DeriveKek(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> headerSalt)
    {
        byte[] data = new byte[KekLabel.Length + headerSalt.Length];
        KekLabel.CopyTo(data, 0);
        headerSalt.CopyTo(data.AsSpan(KekLabel.Length));
        return HMACSHA256.HashData(secret, data);
    }

    // ---------------------------------------------------------------- header

    /// <summary>Read+validate the header page. Throws <see cref="VaultException"/> on bad magic.</summary>
    internal static VaultHeader ReadHeader(ReadOnlySpan<byte> page)
    {
        if (page.Length < HeaderSize
            || !page[..HeaderMagic.Length].SequenceEqual(HeaderMagic))
            throw new VaultException("not a CryptoKey vault image");
        uint version = BinaryPrimitives.ReadUInt32LittleEndian(page[OffVersion..]);
        if (version != FormatVersion)
            throw new VaultException($"unsupported vault format v{version}");
        var slots = new VaultKeySlot[KeySlots];
        for (int i = 0; i < KeySlots; i++)
        {
            int at = OffKeySlot + i * KeySlotLen;
            slots[i] = new VaultKeySlot(
                BinaryPrimitives.ReadUInt32LittleEndian(page[(at + SlotGenOff)..]),
                page.Slice(at + SlotNonceOff, NonceLen).ToArray(),
                page.Slice(at + SlotWrapOff, WrappedKeyLen).ToArray());
        }
        return new VaultHeader(
            version,
            BinaryPrimitives.ReadUInt32LittleEndian(page[OffFlags..]),
            page.Slice(OffSalt, SaltLen).ToArray(),
            slots,
            BinaryPrimitives.ReadUInt64LittleEndian(page[OffManifestSeq..]),
            BinaryPrimitives.ReadUInt64LittleEndian(page[(OffManifestSeq + 8)..]),
            BinaryPrimitives.ReadUInt32LittleEndian(page[OffChunkCount..]),
            BinaryPrimitives.ReadUInt64LittleEndian(page[OffChunkBase..]));
    }

    internal static byte[] WriteHeader(in VaultHeader h)
    {
        byte[] page = new byte[HeaderSize];
        HeaderMagic.CopyTo(page, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(page.AsSpan(OffVersion), h.Version);
        BinaryPrimitives.WriteUInt32LittleEndian(page.AsSpan(OffFlags), h.Flags);
        h.Salt.CopyTo(page, OffSalt);
        for (int i = 0; i < KeySlots; i++)
        {
            int at = OffKeySlot + i * KeySlotLen;
            BinaryPrimitives.WriteUInt32LittleEndian(page.AsSpan(at + SlotGenOff), h.KeySlots[i].RotationGen);
            h.KeySlots[i].Nonce.CopyTo(page, at + SlotNonceOff);
            h.KeySlots[i].WrappedKey.CopyTo(page, at + SlotWrapOff);
        }
        BinaryPrimitives.WriteUInt64LittleEndian(page.AsSpan(OffManifestSeq), h.ManifestSeq0);
        BinaryPrimitives.WriteUInt64LittleEndian(page.AsSpan(OffManifestSeq + 8), h.ManifestSeq1);
        BinaryPrimitives.WriteUInt32LittleEndian(page.AsSpan(OffChunkCount), h.ChunkCount);
        BinaryPrimitives.WriteUInt64LittleEndian(page.AsSpan(OffChunkBase), h.ChunkRegionBase);
        return page;
    }

    // -------------------------------------------------------------- key slots

    /// <summary>Wrap the volume key under a KEK into a slot blob (gen || nonce || ct+tag).</summary>
    internal static VaultKeySlot WrapVolumeKey(byte[] kek, byte[] volKey, uint rotationGen, int slot)
    {
        if (volKey.Length != VolKeyLen)
            throw new ArgumentException($"volume key must be {VolKeyLen}B", nameof(volKey));
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceLen);
        byte[] wrapped = new byte[WrappedKeyLen];
        using (var gcm = new AesGcm(kek, TagLen))
            gcm.Encrypt(nonce, volKey,
                wrapped.AsSpan(0, VolKeyLen), wrapped.AsSpan(VolKeyLen, TagLen),
                SlotAad(slot, rotationGen));
        return new VaultKeySlot(rotationGen, nonce, wrapped);
    }

    /// <summary>Unwrap one slot under a KEK; null when the GCM tag rejects.</summary>
    internal static byte[]? UnwrapVolumeKey(byte[] kek, VaultKeySlot slot, int slotIndex)
    {
        if (slot.Nonce.Length != NonceLen || slot.WrappedKey.Length != WrappedKeyLen)
            return null;
        byte[] volKey = new byte[VolKeyLen];
        try
        {
            using var gcm = new AesGcm(kek, TagLen);
            gcm.Decrypt(slot.Nonce, slot.WrappedKey.AsSpan(0, VolKeyLen),
                slot.WrappedKey.AsSpan(VolKeyLen, TagLen), volKey,
                SlotAad(slotIndex, slot.RotationGen));
            return volKey;
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(volKey);
            return null;
        }
    }

    private static byte[] SlotAad(int slot, uint gen)
    {
        byte[] aad = new byte[SlotAadLabel.Length + 8];
        SlotAadLabel.CopyTo(aad, 0);
        BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(SlotAadLabel.Length), slot);
        BinaryPrimitives.WriteUInt32LittleEndian(
            aad.AsSpan(SlotAadLabel.Length + 4), gen);
        return aad;
    }

    // ----------------------------------------------------------------- chunks

    /// <summary>Physical offset of chunk <paramref name="index"/>.</summary>
    internal static long ChunkOffset(ulong chunkRegionBase, int index)
        => (long)chunkRegionBase + (long)index * ChunkSize;

    internal static byte[] EncryptChunk(byte[] volKey, int index, ReadOnlySpan<byte> plaintext)
    {
        if (plaintext.Length != ChunkPayload)
            throw new ArgumentException($"chunk plaintext must be {ChunkPayload}B");
        byte[] frame = new byte[ChunkSize];
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceLen);
        nonce.CopyTo(frame, 0);
        using var gcm = new AesGcm(volKey, TagLen);
        gcm.Encrypt(nonce, plaintext,
            frame.AsSpan(NonceLen + TagLen, ChunkPayload),
            frame.AsSpan(NonceLen, TagLen), ChunkAad(index));
        return frame;
    }

    /// <summary>Decrypt a chunk frame into <paramref name="dst"/>; false = tag rejection (tamper).</summary>
    internal static bool TryDecryptChunk(byte[] volKey, int index,
        ReadOnlySpan<byte> frame, Span<byte> dst)
    {
        if (frame.Length != ChunkSize || dst.Length < ChunkPayload)
            throw new ArgumentException("chunk frame/dst size mismatch");
        try
        {
            using var gcm = new AesGcm(volKey, TagLen);
            gcm.Decrypt(frame[..NonceLen],
                frame.Slice(NonceLen + TagLen, ChunkPayload),
                frame.Slice(NonceLen, TagLen),
                dst[..ChunkPayload], ChunkAad(index));
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static byte[] ChunkAad(int index)
    {
        byte[] aad = new byte[ChunkAadLabel.Length + 8];
        ChunkAadLabel.CopyTo(aad, 0);
        BinaryPrimitives.WriteInt64LittleEndian(aad.AsSpan(ChunkAadLabel.Length), index);
        return aad;
    }

    // ---------------------------------------------------------------- manifest

    /// <summary>Seal a manifest payload into a slot blob.</summary>
    internal static byte[] SealManifest(byte[] volKey, int slot, ulong seq, byte[] plaintext)
    {
        if (plaintext.Length > MaxManifestPayload)
            throw new VaultException(
                $"manifest payload {plaintext.Length}B exceeds the {MaxManifestPayload}B slot");
        byte[] blob = new byte[ManifestHeadLen + plaintext.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(blob, ManifestMagic);
        BinaryPrimitives.WriteUInt64LittleEndian(blob.AsSpan(4), seq);
        BinaryPrimitives.WriteUInt32LittleEndian(blob.AsSpan(12), (uint)plaintext.Length);
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceLen);
        nonce.CopyTo(blob, 16);
        using var gcm = new AesGcm(volKey, TagLen);
        gcm.Encrypt(nonce, plaintext, blob.AsSpan(ManifestHeadLen),
            blob.AsSpan(28, TagLen), ManifestAad(slot, seq));
        return blob;
    }

    /// <summary>Open a manifest slot blob; null when magic/tag reject (torn or foreign).</summary>
    internal static byte[]? TryOpenManifest(byte[] volKey, int slot,
        ReadOnlySpan<byte> blob, out ulong seq)
    {
        seq = 0;
        if (blob.Length < ManifestHeadLen
            || BinaryPrimitives.ReadUInt32LittleEndian(blob) != ManifestMagic)
            return null;
        seq = BinaryPrimitives.ReadUInt64LittleEndian(blob[4..]);
        uint plainLen = BinaryPrimitives.ReadUInt32LittleEndian(blob[12..]);
        if (plainLen > MaxManifestPayload || blob.Length < ManifestHeadLen + plainLen)
            return null;
        byte[] plain = new byte[plainLen];
        try
        {
            using var gcm = new AesGcm(volKey, TagLen);
            gcm.Decrypt(blob.Slice(16, NonceLen),
                blob.Slice(ManifestHeadLen, (int)plainLen),
                blob.Slice(28, TagLen), plain, ManifestAad(slot, seq));
            return plain;
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    private static byte[] ManifestAad(int slot, ulong seq)
    {
        byte[] aad = new byte[ManifestAadLabel.Length + 12];
        ManifestAadLabel.CopyTo(aad, 0);
        BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(ManifestAadLabel.Length), slot);
        BinaryPrimitives.WriteUInt64LittleEndian(
            aad.AsSpan(ManifestAadLabel.Length + 4), seq);
        return aad;
    }
}

/// <summary>Parsed header state — the fields the volume mutates live here.</summary>
internal sealed class VaultHeader
{
    public VaultHeader(uint version, uint flags, byte[] salt, VaultKeySlot[] keySlots,
        ulong manifestSeq0, ulong manifestSeq1, uint chunkCount, ulong chunkRegionBase)
    {
        Version = version;
        Flags = flags;
        Salt = salt;
        KeySlots = keySlots;
        ManifestSeq0 = manifestSeq0;
        ManifestSeq1 = manifestSeq1;
        ChunkCount = chunkCount;
        ChunkRegionBase = chunkRegionBase;
    }

    public uint Version { get; }
    public uint Flags { get; }
    public byte[] Salt { get; }
    public VaultKeySlot[] KeySlots { get; }
    public ulong ManifestSeq0 { get; set; }
    public ulong ManifestSeq1 { get; set; }
    public uint ChunkCount { get; }
    public ulong ChunkRegionBase { get; }
}

internal sealed class VaultKeySlot
{
    public VaultKeySlot(uint rotationGen, byte[] nonce, byte[] wrappedKey)
    {
        RotationGen = rotationGen;
        Nonce = nonce;
        WrappedKey = wrappedKey;
    }

    public uint RotationGen { get; }
    public byte[] Nonce { get; }
    public byte[] WrappedKey { get; }
}

/// <summary>Vault format-level failure (bad magic, unsupported version, oversized manifest).</summary>
internal sealed class VaultException : Exception
{
    public VaultException(string message) : base(message) { }
}

/// <summary>
/// Crypto integrity failure inside an opened vault — a tampered/corrupt
/// chunk or manifest. Maps to an I/O error at the filesystem layer.
/// </summary>
internal sealed class VaultIntegrityException : Exception
{
    public VaultIntegrityException(string message) : base(message) { }
}
