using System.Security.Cryptography;

namespace CryptoKey;

/// <summary>
/// TPM-backed vault pepper protector via CNG: a persisted RSA-2048 key in
/// the Microsoft Platform Crypto Provider, named <c>CryptoKeyVault</c>,
/// scoped to the current user. Wrap/unwrap is RSA-OAEP-SHA256 through
/// NCrypt — 256B ciphertexts, matching the v3 header's blob field.
///
/// Honest bounds (docs/security-model.md carries the same):
/// the key is user-scoped — same-user malware can call NCryptDecrypt while
/// the TPM is healthy; the binding is per-machine-and-user, not per-owner.
/// NCryptDecrypt is unauthenticated — no PIN/ACL from CNG alone. PCR binding
/// is future work via TBS. Every failure maps to null/false — a TPM hiccup
/// downgrades to phrase recovery, never to a crash.
/// </summary>
internal sealed class WinVaultTpm : IVaultTpm
{
    private static readonly CngProvider TpmProvider =
        new("Microsoft Platform Crypto Provider");
    private const string KeyName = "CryptoKeyVault";
    private const int RsaBits = 2048;

    /// <summary>Provider answers — the key itself may not exist yet.</summary>
    public bool Available
    {
        get
        {
            try
            {
                // Exists() opens the provider — a missing/broken TPM
                // surfaces as CryptographicException here.
                _ = CngKey.Exists(KeyName, TpmProvider);
                return true;
            }
            catch (CryptographicException) { return false; }
            catch (PlatformNotSupportedException) { return false; }
        }
    }

    public byte[]? WrapPepper(byte[] pepper)
    {
        try
        {
            using var rsa = OpenOrCreateRsa();
            return rsa?.Encrypt(pepper, RSAEncryptionPadding.OaepSHA256);
        }
        catch (CryptographicException) { return null; }
        catch (PlatformNotSupportedException) { return null; }
    }

    public byte[]? UnwrapPepper(byte[] blob)
    {
        try
        {
            using var rsa = OpenRsa();
            return rsa?.Decrypt(blob, RSAEncryptionPadding.OaepSHA256);
        }
        catch (CryptographicException) { return null; }
        catch (PlatformNotSupportedException) { return null; }
    }

    public void DeleteKey()
    {
        try
        {
            if (CngKey.Exists(KeyName, TpmProvider))
                CngKey.Open(KeyName, TpmProvider).Delete();
        }
        catch (CryptographicException) { }
        catch (PlatformNotSupportedException) { }
    }

    /// <summary>Open the persisted key if it exists; null when absent or broken.</summary>
    private static RSACng? OpenRsa()
    {
        if (!CngKey.Exists(KeyName, TpmProvider))
            return null;
        return new RSACng(CngKey.Open(KeyName, TpmProvider));
    }

    /// <summary>Open the key, creating it in the TPM provider on first bind.</summary>
    private static RSACng? OpenOrCreateRsa()
    {
        CngKey key = CngKey.Exists(KeyName, TpmProvider)
            ? CngKey.Open(KeyName, TpmProvider)
            : CngKey.Create(CngAlgorithm.Rsa, KeyName, new CngKeyCreationParameters
            {
                Provider = TpmProvider,
                // Non-exportable: the private half never leaves the TPM's
                // boundary — a copied image + cloned keyfile die on the
                // next machine because the pepper can't unwrap there.
                ExportPolicy = CngExportPolicies.None,
                Parameters =
                {
                    new CngProperty("Length",
                        BitConverter.GetBytes(RsaBits), CngPropertyOptions.None),
                },
            });
        return new RSACng(key);
    }
}
