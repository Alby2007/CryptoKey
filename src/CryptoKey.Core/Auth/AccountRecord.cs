using System.Security.Cryptography;

namespace CryptoKey;

/// <summary>
/// The locally-attested half of the cloud account: enough to recognize the
/// account and verify its password OFFLINE, without ever storing the
/// password or tokens. Serialized inside <see cref="KeyConfig.Account"/>
/// (so the keyfile attestation MAC covers it — a grafted verifier trips
/// the next key verify) and inside account.pending.json before enrollment.
///
/// Verifier = PBKDF2-SHA256(password, salt, 600k) — same construction and
/// iteration floor as the recovery-phrase hash. Never a session token:
/// this record can no more sign you in remotely than the phrase hash can.
/// </summary>
internal sealed class AccountRecord
{
    public const int VerifierIterationsCurrent = 600_000;
    public const int VerifierSaltBytes = 16;
    public const int VerifierHashBytes = 32;

    public string UserId { get; set; } = "";
    public string Email { get; set; } = "";
    public string VerifierSalt { get; set; } = "";
    public string VerifierHash { get; set; } = "";
    public int VerifierIterations { get; set; } = VerifierIterationsCurrent;

    /// <summary>
    /// The explicit "protection off" latch — set only by a gated
    /// <c>auth signout</c>, cleared by any real sign-in. Persisted inside
    /// the attested record so it survives restarts AND can't be flipped in
    /// the file without tripping the keyfile MAC (the canon accounthash
    /// slot carries it). This is the ONLY thing that disarms auto-lock on
    /// a bound install — token expiry/offline/restart no longer do.
    /// </summary>
    public bool SignedOut { get; set; }

    /// <summary>
    /// All verifier fields populated — an incomplete record fails closed.
    /// Iterations are bounded BOTH ways: too low weakens the verifier, too
    /// high turns <see cref="VerifyPassword"/> into a hang (a crafted
    /// pending/grafted record could request ~2^31 rounds of PBKDF2).
    /// </summary>
    public bool IsComplete
        => UserId.Length > 0 && Email.Length > 0
           && VerifierSalt.Length > 0 && VerifierHash.Length > 0
           && VerifierIterations is >= 1_000 and <= 4_000_000;

    /// <summary>
    /// Build a record fresh from a successful sign-in/up: user identity from
    /// the server, verifier derived locally from the password in hand.
    /// </summary>
    public static AccountRecord Create(string userId, string email,
        ReadOnlySpan<char> password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(VerifierSaltBytes);
        byte[] hash = Derive(password, salt, VerifierIterationsCurrent);
        return new AccountRecord
        {
            UserId = userId,
            Email = email,
            VerifierSalt = Convert.ToBase64String(salt),
            VerifierHash = Convert.ToBase64String(hash),
            VerifierIterations = VerifierIterationsCurrent,
        };
    }

    /// <summary>Re-derive the verifier after a password change.</summary>
    public void RewriteVerifier(ReadOnlySpan<char> newPassword)
    {
        AccountRecord fresh = Create(UserId, Email, newPassword);
        VerifierSalt = fresh.VerifierSalt;
        VerifierHash = fresh.VerifierHash;
        VerifierIterations = fresh.VerifierIterations;
    }

    /// <summary>
    /// Fixed-time verify against the stored PBKDF2 verifier. A malformed
    /// record (bad base64, wrong lengths) is just a wrong password — never
    /// throws, never accepts.
    /// </summary>
    public bool VerifyPassword(ReadOnlySpan<char> password)
    {
        if (password.IsEmpty || !IsComplete)
            return false;
        byte[]? derived = null;
        try
        {
            byte[] salt = Convert.FromBase64String(VerifierSalt);
            byte[] expected = Convert.FromBase64String(VerifierHash);
            if (salt.Length != VerifierSaltBytes || expected.Length != VerifierHashBytes)
                return false;
            derived = Derive(password, salt, VerifierIterations);
            return CryptographicOperations.FixedTimeEquals(derived, expected);
        }
        catch (Exception)
        {
            return false;
        }
        finally
        {
            if (derived != null)
                CryptographicOperations.ZeroMemory(derived);
        }
    }

    private static byte[] Derive(ReadOnlySpan<char> password, byte[] salt, int iterations)
        => Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations,
            HashAlgorithmName.SHA256, VerifierHashBytes);
}
