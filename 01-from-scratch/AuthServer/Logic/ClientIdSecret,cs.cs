using System.Security.Cryptography;

namespace AuthServer.Logic;

public static class ClientIdSecret
{
    public static string NewClientId(int bytes = 18) // ~24 chars base64url
        => B64Url(RandomNumberGenerator.GetBytes(bytes));

    public static string NewClientSecret(int bytes = 32) // ~43 chars base64url
        => B64Url(RandomNumberGenerator.GetBytes(bytes));

    private static string B64Url(byte[] b)
        => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
