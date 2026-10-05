using System.Security.Cryptography;
using System.Text;

namespace CryptoKey;

/// <summary>
/// The macOS <see cref="IKeyProtector"/>: macOS has no per-blob DPAPI
/// equivalent, so a random 256-bit AES-GCM wrap key lives in the login
/// Keychain instead — which is itself sealed by the user's login password
/// and machine state. <c>kSecAttrAccessibleWhenUnlockedThisDeviceOnly</c>
/// keeps the key out of iCloud and unusable while locked. The entropy blob
/// becomes additional authenticated data, so a ciphertext minted for the
/// keyfile envelope can't be transplanted to another caller.
/// </summary>
internal sealed class KeychainProtector : IKeyProtector
{
    private const string Service = "CryptoKey";
    private const string Account = "keyfile-wrap-v2";
    private const int KeyBytes = 32;
    private const int NonceBytes = 12;
    private const int TagBytes = 16;

    private byte[]? _wrapKey; // fetched once, then cached for process life

    public byte[] Protect(byte[] data, byte[] entropy)
    {
        byte[] key = WrapKey();
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceBytes);
        byte[] cipher = new byte[data.Length];
        byte[] tag = new byte[TagBytes];
        using (var aes = new AesGcm(key, TagBytes))
            aes.Encrypt(nonce, data, cipher, tag, entropy);
        CryptographicOperations.ZeroMemory(key);
        byte[] blob = new byte[NonceBytes + TagBytes + cipher.Length];
        Buffer.BlockCopy(nonce, 0, blob, 0, NonceBytes);
        Buffer.BlockCopy(tag, 0, blob, NonceBytes, TagBytes);
        Buffer.BlockCopy(cipher, 0, blob, NonceBytes + TagBytes, cipher.Length);
        return blob;
    }

    public byte[] Unprotect(byte[] data, byte[] entropy)
    {
        if (data.Length <= NonceBytes + TagBytes)
            throw new CryptographicException("blob too short");
        byte[] key = WrapKey();
        byte[] plain = new byte[data.Length - NonceBytes - TagBytes];
        bool ok = false;
        try
        {
            using (var aes = new AesGcm(key, TagBytes))
                aes.Decrypt(data.AsSpan(0, NonceBytes),
                    data.AsSpan(NonceBytes + TagBytes),
                    data.AsSpan(NonceBytes, TagBytes),
                    plain, entropy);
            ok = true;
            return plain;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            if (!ok)
                CryptographicOperations.ZeroMemory(plain);
        }
    }

    /// <summary>
    /// A COPY of the wrap key — callers wipe the copy after use; the cache
    /// stays intact for the process lifetime.
    /// </summary>
    private byte[] WrapKey()
    {
        if (_wrapKey != null)
            return (byte[])_wrapKey.Clone();

        IntPtr kClass = IntPtr.Zero, kService = IntPtr.Zero, kAccount = IntPtr.Zero,
               kReturnData = IntPtr.Zero, vClass = IntPtr.Zero, vService = IntPtr.Zero,
               vAccount = IntPtr.Zero, vAccessible = IntPtr.Zero, kAccessible = IntPtr.Zero;
        IntPtr query = IntPtr.Zero;
        try
        {
            kClass = MacInterop.CfStr("class");
            kService = MacInterop.CfStr("svce");
            kAccount = MacInterop.CfStr("acct");
            kReturnData = MacInterop.CfStr("r_Data");
            vClass = MacInterop.CfStr("genp");
            vService = MacInterop.CfStr(Service);
            vAccount = MacInterop.CfStr(Account);
            // kSecAttrAccessibleWhenUnlockedThisDeviceOnly — exported symbol,
            // fetched rather than hard-coded.
            vAccessible = MacInterop.ExportedRef(
                "/System/Library/Frameworks/Security.framework/Security",
                "kSecAttrAccessibleWhenUnlockedThisDeviceOnly");
            kAccessible = MacInterop.CfStr("pdmn");
            IntPtr cfTrue = MacInterop.ExportedRef(
                "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
                "kCFBooleanTrue");

            query = MacInterop.CfDict(kClass, vClass, kService, vService,
                kAccount, vAccount, kReturnData, cfTrue);
            int st = MacInterop.SecItemCopyMatching(query, out IntPtr item);
            if (st == MacInterop.ErrSecSuccess && item != IntPtr.Zero)
            {
                byte[] found = MacInterop.CfDataToBytes(item);
                MacInterop.CFRelease(item);
                if (found.Length == KeyBytes)
                {
                    _wrapKey = found;
                    return (byte[])_wrapKey.Clone();
                }
            }

            // Missing or malformed — mint a fresh wrap key.
            byte[] fresh = RandomNumberGenerator.GetBytes(KeyBytes);
            IntPtr kValue = IntPtr.Zero, vData = IntPtr.Zero, add = IntPtr.Zero;
            try
            {
                kValue = MacInterop.CfStr("v_Data");
                vData = MacInterop.CFDataCreate(IntPtr.Zero, fresh, (IntPtr)fresh.Length);
                add = MacInterop.CfDict(kClass, vClass, kService, vService,
                    kAccount, vAccount, kAccessible, vAccessible, kValue, vData);
                // A keychain item that exists with the wrong shape is replaced —
                // delete first so Add can't bounce on errSecDuplicateItem. The
                // delete gets a minimal primary-key query: SecItemDelete can
                // errSecParam on return-type keys like r_Data, and a bounced
                // delete is exactly what wedges the add.
                IntPtr del = MacInterop.CfDict(kClass, vClass, kService, vService,
                    kAccount, vAccount);
                try { MacInterop.SecItemDelete(del); }
                finally { MacInterop.CFRelease(del); }
                st = MacInterop.SecItemAdd(add, IntPtr.Zero);
                if (st != MacInterop.ErrSecSuccess)
                    throw new CryptographicException($"Keychain write failed (OSStatus {st})");
            }
            finally
            {
                if (add != IntPtr.Zero) MacInterop.CFRelease(add);
                if (vData != IntPtr.Zero) MacInterop.CFRelease(vData);
                if (kValue != IntPtr.Zero) MacInterop.CFRelease(kValue);
            }
            _wrapKey = fresh;
            return (byte[])_wrapKey.Clone();
        }
        finally
        {
            if (query != IntPtr.Zero) MacInterop.CFRelease(query);
            foreach (IntPtr h in new[] { kClass, kService, kAccount, kReturnData,
                     vClass, vService, vAccount, kAccessible })
                if (h != IntPtr.Zero) MacInterop.CFRelease(h);
            // vAccessible and cfTrue are exported constants — never CFRelease.
        }
    }

}
