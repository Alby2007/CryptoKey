using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CryptoKey;

/// <summary>
/// The CKVAULT1 on-disk format — header, key slots, manifest slots, chunk
/// codec. Pure format layer: no directory tree, no allocator, no state.
///
/// <code>
/// header pages (4 KiB each — primary at 0, shadow at 4096):
///   0   magic "CKVAULT\x01"        8B
///   8   formatVersion u32
///   12  flags u32
///   16  headerSalt 16B
///   32  keySlot[0] 64B  { rotationGen u32 | nonce 12B | wrappedVolKey 48B }
///   96  keySlot[1] 64B
///   160 manifestSeq[0] u64
///   168 manifestSeq[1] u64
///   176 chunkCount u32
///   184 chunkRegionBase u64
///   192 headerCheck 8B  (SHA-256 of page[0..192), truncated)
///
/// v3 extends the header inside the same page (the v2 fields above are
/// untouched — the ext region starts where the v2 checksum used to sit,
/// so reads distinguish by formatVersion):
///   192 extLen u16            — 334 for v3; the region's total span
///   194 tpmPepperBlob 256B    — RSA-2048 OAEP-SHA256(pepper) under the
///                             persisted TPM-bound NCrypt key
///   450 recPepperBlob 64B     — pepper sealed under the recovery phrase
///                             (AES-GCM; zeroed when strict-bound)
///   514 recIters u32          — PBKDF2 iters frozen at enroll
///   518 headerCheck 8B        — SHA-256 of page[0..518), truncated
///
/// The pepper is a 32B machine-binding secret: when Flags.TpmBound is set
/// the KEK is HMAC(secret, label ‖ salt ‖ pepper), so the image opens only
/// where the TPM (or the recovery phrase) can reproduce the pepper. The
/// flag itself is a UX hint — forging it off can't help (the slots simply
/// won't unwrap); forging it on yields a vault that can never open.
///
/// manifest slot i at ManifestBase + i*ManifestSlotSize (4 MiB each):
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

    internal const uint FormatVersion = 3;
    internal const uint MinFormatVersion = 2; // v2 images read + upgrade on next header write
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

    internal const long ShadowBase = HeaderSize;                  // second header copy
    internal const long ManifestBase = HeaderSize * 2;
    internal const long DataOffset = ManifestBase + ManifestSlots * (long)ManifestSlotSize;

    // Header field offsets.
    private const int OffVersion = 8;
    private const int OffFlags = 12;
    private const int OffSalt = 16;
    private const int OffKeySlot = 32;
    private const int OffManifestSeq = OffKeySlot + KeySlots * KeySlotLen; // 160
    private const int OffChunkCount = OffManifestSeq + ManifestSlots * 8;  // 176
    private const int OffChunkBase = OffChunkCount + 8;                    // 184
    private const int OffCheckV2 = OffChunkBase + 8;                       // 192 — v2 layout's check

    // v3 extension region — starts at the old checksum offset.
    private const int OffExt = 192;
    private const int ExtLenV3 = 334;               // whole ext span incl. check
    private const int OffTpmBlob = OffExt + 2;      // 194
    internal const int TpmBlobLen = 256;
    private const int OffRecBlob = OffTpmBlob + TpmBlobLen; // 450
    internal const int RecBlobLen = 64;
    private const int OffRecIters = OffRecBlob + RecBlobLen; // 514
    private const int OffCheckV3 = OffRecIters + 4;          // 518

    private const int CheckLen = 8; // truncated SHA-256 of page[0..checkOff)

    internal const uint FlagTpmBound = 0x1;
    internal const int PepperLen = 32;

    // Key slot field offsets (within a 64B slot).
    private const int SlotGenOff = 0;
    private const int SlotNonceOff = 4;
    private const int SlotWrapOff = 16;

    private static readonly byte[] KekLabel = "CryptoKeyVaultKEK"u8.ToArray();
    private static readonly byte[] SlotAadLabel = "CKVKEYSLOT"u8.ToArray();
    private static readonly byte[] ManifestAadLabel = "CKVMANIFEST"u8.ToArray();
    private static readonly byte[] ChunkAadLabel = "CKVCHUNK"u8.ToArray();
    private static readonly byte[] RecLabel = "CKV-REC"u8.ToArray();

    /// <summary>
    /// Key-wrapping key for a verified device secret + this image's salt
    /// (+ the machine-binding pepper when the image is TPM-bound). An empty
    /// pepper is byte-identical to the v2 derivation.
    /// </summary>
    internal static byte[] DeriveKek(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> headerSalt,
        ReadOnlySpan<byte> pepper = default)
    {
        byte[] data = new byte[KekLabel.Length + headerSalt.Length + pepper.Length];
        KekLabel.CopyTo(data, 0);
        headerSalt.CopyTo(data.AsSpan(KekLabel.Length));
        pepper.CopyTo(data.AsSpan(KekLabel.Length + headerSalt.Length));
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
        if (version is < MinFormatVersion or > FormatVersion)
            throw new VaultException($"unsupported vault format v{version}");
        // v2: check @192 covers page[0..192); v3: check ends the ext region,
        // so extLen > 334 (a future extension) slides the check along with it.
        int checkOff = version == 2 ? OffCheckV2 : V3CheckOff(page);
        if (!SHA256.HashData(page[..checkOff]).AsSpan(0, CheckLen)
                .SequenceEqual(page.Slice(checkOff, CheckLen)))
            throw new VaultException("header checksum mismatch — torn write");
        var slots = new VaultKeySlot[KeySlots];
        for (int i = 0; i < KeySlots; i++)
        {
            int at = OffKeySlot + i * KeySlotLen;
            slots[i] = new VaultKeySlot(
                BinaryPrimitives.ReadUInt32LittleEndian(page[(at + SlotGenOff)..]),
                page.Slice(at + SlotNonceOff, NonceLen).ToArray(),
                page.Slice(at + SlotWrapOff, WrappedKeyLen).ToArray());
        }
        var h = new VaultHeader(
            version,
            BinaryPrimitives.ReadUInt32LittleEndian(page[OffFlags..]),
            page.Slice(OffSalt, SaltLen).ToArray(),
            slots,
            BinaryPrimitives.ReadUInt64LittleEndian(page[OffManifestSeq..]),
            BinaryPrimitives.ReadUInt64LittleEndian(page[(OffManifestSeq + 8)..]),
            BinaryPrimitives.ReadUInt32LittleEndian(page[OffChunkCount..]),
            BinaryPrimitives.ReadUInt64LittleEndian(page[OffChunkBase..]));
        if (version >= 3)
        {
            h.TpmBlob = page.Slice(OffTpmBlob, TpmBlobLen).ToArray();
            h.RecBlob = page.Slice(OffRecBlob, RecBlobLen).ToArray();
            h.RecIters = BinaryPrimitives.ReadUInt32LittleEndian(page[OffRecIters..]);
        }
        return h;
    }

    private static int V3CheckOff(ReadOnlySpan<byte> page)
    {
        uint extLen = BinaryPrimitives.ReadUInt16LittleEndian(page[OffExt..]);
        int checkOff = OffExt + (int)extLen - CheckLen;
        if (extLen < ExtLenV3 || checkOff + CheckLen > HeaderSize)
            throw new VaultException("header extension length out of range");
        return checkOff;
    }

    /// <summary>Always writes v3 — a v2 image upgrades on its next header write.</summary>
    internal static byte[] WriteHeader(in VaultHeader h)
    {
        byte[] page = new byte[HeaderSize];
        HeaderMagic.CopyTo(page, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(page.AsSpan(OffVersion), FormatVersion);
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
        BinaryPrimitives.WriteUInt16LittleEndian(page.AsSpan(OffExt), ExtLenV3);
        h.TpmBlob.AsSpan(0, TpmBlobLen).CopyTo(page.AsSpan(OffTpmBlob));
        h.RecBlob.AsSpan(0, RecBlobLen).CopyTo(page.AsSpan(OffRecBlob));
        BinaryPrimitives.WriteUInt32LittleEndian(page.AsSpan(OffRecIters), h.RecIters);
        SHA256.HashData(page.AsSpan(0, OffCheckV3)).AsSpan(0, CheckLen)
            .CopyTo(page.AsSpan(OffCheckV3));
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

    // --------------------------------------------------- recovery pepper blob

    /// <summary>
    /// Seal the pepper under a recovery-phrase KEK into the 64B blob slot:
    /// nonce 12 | ct 32 | tag 16 | pad 4. <paramref name="phraseKek"/> is
    /// PBKDF2(normalized phrase, "CKV-REC"‖headerSalt, iters) — built by
    /// <see cref="ConfigStore.DeriveRecoveryKek"/>.
    /// </summary>
    internal static byte[] SealRecoveryPepper(byte[] phraseKek, byte[] pepper)
    {
        if (pepper.Length != PepperLen)
            throw new ArgumentException($"pepper must be {PepperLen}B", nameof(pepper));
        byte[] blob = new byte[RecBlobLen];
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceLen);
        nonce.CopyTo(blob, 0);
        using var gcm = new AesGcm(phraseKek, TagLen);
        gcm.Encrypt(nonce, pepper,
            blob.AsSpan(NonceLen, PepperLen),
            blob.AsSpan(NonceLen + PepperLen, TagLen), RecLabel);
        return blob;
    }

    /// <summary>Open a recovery blob under a phrase KEK; null on tag reject.</summary>
    internal static byte[]? TryOpenRecoveryPepper(byte[] phraseKek, ReadOnlySpan<byte> blob)
    {
        if (blob.Length != RecBlobLen)
            return null;
        byte[] pepper = new byte[PepperLen];
        try
        {
            using var gcm = new AesGcm(phraseKek, TagLen);
            gcm.Decrypt(blob[..NonceLen],
                blob.Slice(NonceLen, PepperLen),
                blob.Slice(NonceLen + PepperLen, TagLen), pepper, RecLabel);
            return pepper;
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(pepper);
            return null;
        }
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
    public uint Flags { get; set; }
    public byte[] Salt { get; }
    public VaultKeySlot[] KeySlots { get; }
    public ulong ManifestSeq0 { get; set; }
    public ulong ManifestSeq1 { get; set; }
    public uint ChunkCount { get; }
    public ulong ChunkRegionBase { get; }

    // v3 extension — zero-filled when the image is a v2 header or unbound.
    public byte[] TpmBlob { get; set; } = new byte[VaultFormat.TpmBlobLen];
    public byte[] RecBlob { get; set; } = new byte[VaultFormat.RecBlobLen];
    public uint RecIters { get; set; }

    /// <summary>UX hint flag — see the format doc: it can't protect itself.</summary>
    public bool TpmBound => (Flags & VaultFormat.FlagTpmBound) != 0;

    /// <summary>Whether the image carries a phrase recovery hatch (non-strict bind).</summary>
    public bool HasRecovery => RecIters != 0;
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
