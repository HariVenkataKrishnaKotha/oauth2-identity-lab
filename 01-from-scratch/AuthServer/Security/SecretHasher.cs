using System.Security.Cryptography;

namespace AuthServer.Security;

public static class SecretHasher
{
    public static (byte[] hash, byte[] salt) Hash(string secret, int iterations = 100_000)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(secret, salt, iterations, HashAlgorithmName.SHA256, 32);
        return (hash, salt);
    }

    public static bool Verify(string secret, byte[] hash, byte[] salt, int iterations = 100_000)
    {
        var testHash = Rfc2898DeriveBytes.Pbkdf2(secret, salt, iterations, HashAlgorithmName.SHA256, 32);
        return CryptographicOperations.FixedTimeEquals(testHash, hash);
    }
}
