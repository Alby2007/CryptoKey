using System.Security.Cryptography;
using Xunit;
namespace CryptoKey.Tests;

public class UpdateCheckerTests
{
    // ---- tag parsing ----

    [Theory]
    [InlineData("v0.9.1", 0, 9, 1)]
    [InlineData("v1.0.0", 1, 0, 0)]
    [InlineData("V2.3.4", 2, 3, 4)]
    [InlineData("v1.2.3-rc1", 1, 2, 3)]
    [InlineData("v0.10.0+deadbeef", 0, 10, 0)] // build metadata stripped
    public void TryParseTag_accepts_release_tags(string tag, int maj, int min, int pat)
    {
        Assert.True(UpdateChecker.TryParseTag(tag, out Version v));
        Assert.Equal(new Version(maj, min, pat), v);
    }

    [Theory]
    [InlineData("0.9.1")]     // missing v prefix
    [InlineData("latest")]    // junk
    [InlineData("v")]         // bare v
    [InlineData("v.x.y")]     // non-numeric
    [InlineData("")]
    public void TryParseTag_rejects_non_versions(string tag)
        => Assert.False(UpdateChecker.TryParseTag(tag, out _));

    // ---- version comparison ----

    [Fact]
    public void IsNewer_strictly_greater_only()
    {
        var cur = new Version(0, 9, 0);
        Assert.True(UpdateChecker.IsNewer(new Version(0, 9, 1), cur));
        Assert.True(UpdateChecker.IsNewer(new Version(1, 0, 0), cur));
        Assert.False(UpdateChecker.IsNewer(new Version(0, 9, 0), cur));  // same — no re-offer
        Assert.False(UpdateChecker.IsNewer(new Version(0, 8, 9), cur));  // downgrade refused
    }

    // ---- manifest parsing ----

    [Fact]
    public void ParseSha256Sums_standard_lines_and_comments()
    {
        string manifest =
            "# release: v1.0.0\n" +
            "aabbccdd  cryptokey-win-x64.zip\n" +
            "eeff0011 *other.bin\n"; // binary-mode marker
        var sums = UpdateChecker.ParseSha256Sums(manifest);
        Assert.Equal("aabbccdd", sums["cryptokey-win-x64.zip"]);
        Assert.Equal("eeff0011", sums["other.bin"]);
        Assert.Single(sums.Where(k => !k.Key.StartsWith('#')).Skip(1)); // zip + other, comment skipped
    }

    [Fact]
    public void ManifestTag_reads_release_binding()
    {
        Assert.Equal("v1.2.3",
            UpdateChecker.ManifestTag("# release: v1.2.3\nabc  f.zip\n"));
        Assert.Null(UpdateChecker.ManifestTag("abc  f.zip\n# other: x\n"));
    }

    // ---- signature verify (pinned key) ----

    [Fact]
    public void Verify_rejects_placeholder_key()
    {
        // The checked-in PinnedPubKeyB64 is a placeholder until a real
        // maintainer key is generated — every signature must fail-closed.
        if (ReleaseSigning.PinnedPubKeyB64.Contains("PLACEHOLDER"))
        {
            Assert.False(ReleaseSigning.Verify(new byte[] { 1, 2, 3 }, new byte[64]));
        }
    }

    [Fact]
    public void Sign_verify_round_trip_and_tamper()
    {
        (byte[] priv, string pub) = ReleaseSigning.GenerateKey();
        byte[] data = System.Text.Encoding.UTF8.GetBytes("# release: v9.9.9\nabc  f.zip\n");
        byte[] sig = ReleaseSigning.Sign(data, priv);
        Assert.Equal(64, sig.Length); // P1363 r‖s, P-256 → 2×32

        // The real Verify path (key injected) — positive accept…
        Assert.True(ReleaseSigning.Verify(data, sig, pub));
        // …byte-flipped manifest rejects…
        byte[] tampered = (byte[])data.Clone();
        tampered[5] ^= 0xFF;
        Assert.False(ReleaseSigning.Verify(tampered, sig, pub));
        // …a different signer's signature rejects…
        (byte[] priv2, _) = ReleaseSigning.GenerateKey();
        Assert.False(ReleaseSigning.Verify(data, ReleaseSigning.Sign(data, priv2), pub));
        // …and a valid sig under a WRONG trusted key rejects.
        Assert.False(ReleaseSigning.Verify(data, sig,
            ReleaseSigning.GenerateKey().publicKeyB64));
    }

    [Fact]
    public void Sign_pem_round_trip()
    {
        (string pem, string pub) = ReleaseSigning.GenerateKeyPem();
        byte[] data = new byte[] { 42 };
        byte[] sig = ReleaseSigning.Sign(data, pem);
        using var ec = ECDsa.Create();
        ec.ImportSubjectPublicKeyInfo(Convert.FromBase64String(pub), out _);
        Assert.True(ec.VerifyData(data, sig, HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }

    // ---- sha256 helper ----

    [Fact]
    public void Sha256Hex_matches_known_vector()
    {
        string path = Path.Combine(Path.GetTempPath(), $"ck-sha-{Guid.NewGuid():N}");
        try
        {
            File.WriteAllBytes(path, System.Text.Encoding.ASCII.GetBytes("abc"));
            // FIPS 180-4 vector: sha256("abc")
            Assert.Equal(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                UpdateChecker.Sha256Hex(path));
        }
        finally { File.Delete(path); }
    }

    // ---- the full trust gate: sign → manifest → hash → extract ----

    private static (UpdateInfo info, string manifest, string sig, string zip, string dir)
        StageFixture(string tag = "v9.9.9")
    {
        string dir = Path.Combine(Path.GetTempPath(), $"ck-upd-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        string zipPath = Path.Combine(dir, UpdateChecker.ZipName);
        using (var zip = System.IO.Compression.ZipFile.Open(zipPath,
            System.IO.Compression.ZipArchiveMode.Create))
            zip.CreateEntry("cryptokey.exe");
        string manifest = $"# release: {tag}\n{UpdateChecker.Sha256Hex(zipPath)}  {UpdateChecker.ZipName}\n";
        string manifestPath = Path.Combine(dir, "SHA256SUMS.txt");
        File.WriteAllText(manifestPath, manifest);
        return (new UpdateInfo
        {
            TagName = tag,
            Version = new Version(9, 9, 9),
            ZipUrl = "x", ManifestUrl = "x", SigUrl = "x",
        }, manifestPath, Path.Combine(dir, UpdateChecker.SigName), zipPath, dir);
    }

    [Fact]
    public void VerifyAndExtract_accepts_signed_fixture()
    {
        (byte[] priv, string pub) = ReleaseSigning.GenerateKey();
        var (info, manifestPath, sigPath, zipPath, dir) = StageFixture();
        try
        {
            File.WriteAllBytes(sigPath,
                ReleaseSigning.Sign(File.ReadAllBytes(manifestPath), priv));
            string payload = UpdateChecker.VerifyAndExtract(
                info, manifestPath, sigPath, zipPath, dir, publicKeyB64: pub);
            Assert.True(File.Exists(Path.Combine(payload, "cryptokey.exe")));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void VerifyAndExtract_rejects_wrong_signer_and_tampered_zip()
    {
        (byte[] priv, string pub) = ReleaseSigning.GenerateKey();
        var (info, manifestPath, sigPath, zipPath, dir) = StageFixture();
        try
        {
            File.WriteAllBytes(sigPath,
                ReleaseSigning.Sign(File.ReadAllBytes(manifestPath), priv));
            // A zip that doesn't match the manifest's hash → refuse.
            File.AppendAllText(zipPath, "tampered");
            Assert.Throws<UpdateException>(() => UpdateChecker.VerifyAndExtract(
                info, manifestPath, sigPath, zipPath, dir, publicKeyB64: pub));

            // A manifest signed by a DIFFERENT key → refuse.
            (byte[] otherPriv, _) = ReleaseSigning.GenerateKey();
            File.WriteAllBytes(sigPath,
                ReleaseSigning.Sign(File.ReadAllBytes(manifestPath), otherPriv));
            Assert.Throws<UpdateException>(() => UpdateChecker.VerifyAndExtract(
                info, manifestPath, sigPath, zipPath, dir, publicKeyB64: pub));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void VerifyAndExtract_rejects_unbound_manifest()
    {
        // M1 — tag binding is required: an unsigned-era manifest replayed
        // under a newer tag must fail closed on absence, not pass.
        (byte[] priv, string pub) = ReleaseSigning.GenerateKey();
        var (info, manifestPath, sigPath, zipPath, dir) = StageFixture();
        try
        {
            string unbound = File.ReadAllText(manifestPath)
                .Replace("# release: v9.9.9\n", "");
            File.WriteAllText(manifestPath, unbound);
            File.WriteAllBytes(sigPath,
                ReleaseSigning.Sign(File.ReadAllBytes(manifestPath), priv));
            Assert.Throws<UpdateException>(() => UpdateChecker.VerifyAndExtract(
                info, manifestPath, sigPath, zipPath, dir, publicKeyB64: pub));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void VerifyAndExtract_rejects_tag_mismatch()
    {
        (byte[] priv, string pub) = ReleaseSigning.GenerateKey();
        var (info, manifestPath, sigPath, zipPath, dir) = StageFixture(tag: "v9.9.9");
        try
        {
            File.WriteAllBytes(sigPath,
                ReleaseSigning.Sign(File.ReadAllBytes(manifestPath), priv));
            var mismatched = new UpdateInfo
            {
                TagName = "v9.9.8", // release tag ≠ manifest's bound tag
                Version = new Version(9, 9, 8),
                ZipUrl = "x", ManifestUrl = "x", SigUrl = "x",
            };
            Assert.Throws<UpdateException>(() => UpdateChecker.VerifyAndExtract(
                mismatched, manifestPath, sigPath, zipPath, dir, publicKeyB64: pub));
        }
        finally { Directory.Delete(dir, true); }
    }
}
