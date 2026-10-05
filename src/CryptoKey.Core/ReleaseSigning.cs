using System.Security.Cryptography;

namespace CryptoKey;

/// <summary>
/// Release-manifest signing — ECDSA-P256, IEEE-P1363 r‖s signatures.
/// The public key is pinned in source (<see cref="PinnedPubKeyB64"/>); the
/// private key lives only on the maintainer's machine via
/// <c>cryptokey sign-release</c>. A release the app accepts must carry a
/// manifest signed by that key — a compromised GitHub account alone can't
/// forge one.
/// </summary>
internal static class ReleaseSigning
{
    /// <summary>
    /// Maintainer public key (SubjectPublicKeyInfo, base64). Generated once
    /// by `cryptokey sign-release --gen-key`; rotating it ships as a normal
    /// release.
    /// </summary>
    internal const string PinnedPubKeyB64 =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESeC5rON1GKNeCJjw+PF6c2cC9A2KuaSUEM2EAk76xpKsWtYYhzKydUi8UubtOYKNeZIe/zXft/b3Pal9K8Hg3Q==";

    /// <summary>Generate a maintainer keypair — returns PKCS8 private + SPKI public (base64).</summary>
    public static (byte[] privateKey, string publicKeyB64) GenerateKey()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return (ec.ExportPkcs8PrivateKey(),
            Convert.ToBase64String(ec.ExportSubjectPublicKeyInfo()));
    }

    /// <summary>Generate a maintainer keypair — PKCS8-PEM private (for a key file) + SPKI-base64 public.</summary>
    public static (string privatePem, string publicKeyB64) GenerateKeyPem()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return (ec.ExportPkcs8PrivateKeyPem(),
            Convert.ToBase64String(ec.ExportSubjectPublicKeyInfo()));
    }

    /// <summary>Sign <paramref name="data"/> with a PEM-encoded PKCS8 key — 64-byte P1363.</summary>
    public static byte[] Sign(byte[] data, string pkcs8Pem)
    {
        using var ec = ECDsa.Create();
        ec.ImportFromPem(pkcs8Pem);
        return ec.SignData(data, HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    /// <summary>The public half of a maintainer keypair (SPKI, base64) — for printing/embedding.</summary>
    public static string PublicKeyB64(ReadOnlySpan<byte> pkcs8)
    {
        using var ec = ECDsa.Create();
        ec.ImportPkcs8PrivateKey(pkcs8, out _);
        return Convert.ToBase64String(ec.ExportSubjectPublicKeyInfo());
    }

    /// <summary>Sign <paramref name="data"/> — 64-byte P1363 signature.</summary>
    public static byte[] Sign(byte[] data, ReadOnlySpan<byte> pkcs8)
    {
        using var ec = ECDsa.Create();
        ec.ImportPkcs8PrivateKey(pkcs8, out _);
        return ec.SignData(data, HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    /// <summary>
    /// Verify a P1363 signature against the pinned maintainer key.
    /// <paramref name="publicKeyB64"/> overrides the pin — tests only;
    /// production callers must omit it.
    /// </summary>
    public static bool Verify(byte[] data, byte[] signature, string? publicKeyB64 = null)
    {
        try
        {
            using var ec = ECDsa.Create();
            ec.ImportSubjectPublicKeyInfo(
                Convert.FromBase64String(publicKeyB64 ?? PinnedPubKeyB64), out _);
            return ec.VerifyData(data, signature, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (Exception)
        {
            return false; // malformed key blob or signature — never throw
        }
    }
}
