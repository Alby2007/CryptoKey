using System.Security.Cryptography;

namespace CryptoKey;

/// <summary>
/// The recovery phrase — CryptoKey's only user credential. Generated, never
/// chosen: 20 Crockford Base32 characters (~100 bits) displayed grouped as
/// XXXXX-XXXXX-XXXXX-XXXXX. Verification always normalizes first, so
/// lowercase entry, missing or extra separators, and ambiguous-glyph slips
/// (O→0, I/L→1) still match the stored hash.
/// </summary>
internal static class RecoveryPhrase
{
    /// <summary>Crockford Base32 — no I, L, O, or U (drops the 0/1 lookalikes).</summary>
    public const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    /// <summary>Canonical phrase length — characters after normalization.</summary>
    public const int ExpectedLength = 20;

    private const int GroupSize = 5;

    /// <summary>Generate a new phrase, grouped XXXXX-XXXXX-XXXXX-XXXXX.</summary>
    public static string Generate()
    {
        Span<char> chars = stackalloc char[ExpectedLength + 3];
        int i = 0;
        for (int c = 0; c < ExpectedLength; c++)
        {
            if (c > 0 && c % GroupSize == 0)
                chars[i++] = '-';
            chars[i++] = Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)];
        }
        return new string(chars);
    }

    /// <summary>
    /// Canonicalize typed input into <paramref name="dest"/>: uppercase,
    /// keep letters/digits only (dashes, spaces, and stray punctuation are
    /// dropped), and fold the ambiguous glyphs the alphabet excludes —
    /// O→0, I→1, L→1 — so transcription slips still verify. Returns the
    /// total normalized length; when it exceeds <paramref name="dest"/>'s
    /// capacity, dest holds only a truncated prefix.
    /// </summary>
    public static int Normalize(ReadOnlySpan<char> input, Span<char> dest)
    {
        int n = 0;
        foreach (char raw in input)
        {
            char c = char.ToUpperInvariant(raw) switch
            {
                'O' => '0',
                'I' or 'L' => '1',
                var x => x,
            };
            if (!char.IsLetterOrDigit(c))
                continue;
            if (n < dest.Length)
                dest[n] = c;
            n++;
        }
        return n;
    }

    /// <summary>True when a normalized span is exactly the expected length and alphabet.</summary>
    public static bool IsValid(ReadOnlySpan<char> normalized)
    {
        if (normalized.Length != ExpectedLength)
            return false;
        foreach (char c in normalized)
            if (!Alphabet.Contains(c))
                return false;
        return true;
    }
}
