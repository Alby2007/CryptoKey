using System.Security.Cryptography;
using Xunit;
namespace CryptoKey.Tests;

public class RecoveryPhraseTests
{
    // A 20-char canonical phrase, all alphabet: digits + A-H + J,K.
    private const string Canonical = "0123456789ABCDEFGHJK";

    [Fact]
    public void Generate_format_is_grouped_alphabet()
    {
        string p = RecoveryPhrase.Generate();
        // XXXXX-XXXXX-XXXXX-XXXXX — 20 alphabet chars + 3 group dashes.
        Assert.Equal(23, p.Length);
        for (int i = 0; i < p.Length; i++)
        {
            if (i is 5 or 11 or 17)
                Assert.Equal('-', p[i]);
            else
                Assert.Contains(p[i], RecoveryPhrase.Alphabet);
        }
    }

    [Fact]
    public void Generate_produces_distinct_phrases()
        => Assert.NotEqual(RecoveryPhrase.Generate(), RecoveryPhrase.Generate());

    [Fact]
    public void Alphabet_is_unambiguous()
    {
        // Crockford Base32 — no I, L, O, U (drops the 0/1 lookalikes).
        Assert.Equal(32, RecoveryPhrase.Alphabet.Length);
        foreach (char c in "ILOU")
            Assert.DoesNotContain(c, RecoveryPhrase.Alphabet);
    }

    [Fact]
    public void Normalize_strips_separators_and_uppercases()
    {
        Span<char> buf = stackalloc char[32];
        int n = RecoveryPhrase.Normalize("abcde-fghij klmno", buf);
        // 'i'→'1', 'l'→'1', 'o'→'0' — the alphabet has no real I/L/O.
        Assert.Equal("ABCDEFGH1JK1MN0", new string(buf[..n]));
    }

    [Fact]
    public void Normalize_folds_ambiguous_glyphs()
    {
        Span<char> buf = stackalloc char[32];
        int n = RecoveryPhrase.Normalize("oOiIlL", buf);
        Assert.Equal("001111", new string(buf[..n]));
    }

    [Fact]
    public void Normalize_reports_total_when_dest_is_short()
    {
        Span<char> buf = stackalloc char[4];
        int n = RecoveryPhrase.Normalize("ABCDEFGH", buf);
        Assert.Equal(8, n);
        Assert.Equal("ABCD", new string(buf));
    }

    [Fact]
    public void IsValid_checks_length_and_alphabet()
    {
        Assert.True(RecoveryPhrase.IsValid(Canonical));
        Assert.False(RecoveryPhrase.IsValid("0123456789ABCDEFGHJ"));    // 19
        Assert.False(RecoveryPhrase.IsValid("0123456789ABCDEFGHJU"));  // 'U' isn't alphabet
        Assert.False(RecoveryPhrase.IsValid(""));
    }

    [Fact]
    public void Generated_phrase_roundtrips()
    {
        string phrase = RecoveryPhrase.Generate();
        KeyConfig config = ConfigStore.CreateNew("S", TestDisk.RandomSecret(), phrase);
        Assert.True(ConfigStore.VerifyPassphrase(config, phrase));
    }

    [Fact]
    public void Typed_variants_verify()
    {
        string phrase = RecoveryPhrase.Generate();
        KeyConfig config = ConfigStore.CreateNew("S", TestDisk.RandomSecret(), phrase);
        Assert.True(ConfigStore.VerifyPassphrase(config, phrase.Replace("-", "")));
        Assert.True(ConfigStore.VerifyPassphrase(config, phrase.ToLowerInvariant()));
        Assert.True(ConfigStore.VerifyPassphrase(config, $" {phrase} \n"));
    }

    [Fact]
    public void Ambiguous_glyphs_verify()
    {
        KeyConfig config = ConfigStore.CreateNew("S", TestDisk.RandomSecret(), Canonical);
        Assert.True(ConfigStore.VerifyPassphrase(config, Canonical));
        Assert.True(ConfigStore.VerifyPassphrase(config, "O123456789ABCDEFGHJK"));  // O→0
        Assert.True(ConfigStore.VerifyPassphrase(config, "0i23456789abcdefghjk"));  // i→1
        Assert.True(ConfigStore.VerifyPassphrase(config, "0L23456789ABCDEFGHJK"));  // L→1
    }

    [Fact]
    public void Wrong_phrase_fails()
    {
        string phrase = RecoveryPhrase.Generate();
        KeyConfig config = ConfigStore.CreateNew("S", TestDisk.RandomSecret(), phrase);
        Assert.False(ConfigStore.VerifyPassphrase(config, RecoveryPhrase.Generate()));
        Assert.False(ConfigStore.VerifyPassphrase(config, "hunter2"));
    }

    [Fact]
    public void Trailing_junk_does_not_verify()
    {
        // The correct phrase plus a stray extra char is NOT the phrase —
        // normalization never truncates to a match.
        string phrase = RecoveryPhrase.Generate();
        KeyConfig config = ConfigStore.CreateNew("S", TestDisk.RandomSecret(), phrase);
        Assert.False(ConfigStore.VerifyPassphrase(config, phrase + "X"));
    }

    /// <summary>
    /// Force-migration, documented: a config written by the pre-phrase build
    /// hashed the raw passphrase. Verify now normalizes the input, so the
    /// old credential fails — the path back is regenerating the phrase
    /// (authorized by the enrolled key on the Security tab).
    /// </summary>
    [Fact]
    public void Legacy_raw_passphrase_fails_verify()
    {
        KeyConfig config = ConfigStore.CreateNew("S", TestDisk.RandomSecret(),
            RecoveryPhrase.Generate());
        byte[] salt = Convert.FromBase64String(config.PassphraseSalt);
        config.PassphraseHash = Convert.ToBase64String(
            Rfc2898DeriveBytes.Pbkdf2("My old passphrase!", salt, config.PassphraseIterations,
                HashAlgorithmName.SHA256, 32));
        Assert.False(ConfigStore.VerifyPassphrase(config, "My old passphrase!"));
    }
}
