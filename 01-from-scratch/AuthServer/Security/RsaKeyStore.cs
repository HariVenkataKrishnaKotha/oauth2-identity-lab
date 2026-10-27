using System.Security.Cryptography;

namespace AuthServer.Security;

public sealed class RsaKeyStore
{
    private readonly string _dir;
    public RsaKeyStore(string dir) => _dir = dir;

    public (RSA privateKey, RSA publicKey) GetOrCreate()
    {
        Directory.CreateDirectory(_dir);
        var privPath = Path.Combine(_dir, "rsa-private.pem");
        var pubPath = Path.Combine(_dir, "rsa-public.pem");

        if (File.Exists(privPath) && File.Exists(pubPath))
        {
            var priv = RSA.Create(); priv.ImportFromPem(File.ReadAllText(privPath));
            var pub = RSA.Create(); pub.ImportFromPem(File.ReadAllText(pubPath));
            return (priv, pub);
        }

        using var rsa = RSA.Create(2048);
        var privPem = ExportPrivatePem(rsa);
        var pubPem = ExportPublicPem(rsa);
        File.WriteAllText(privPath, privPem);
        File.WriteAllText(pubPath, pubPem);

        var privLoaded = RSA.Create(); privLoaded.ImportFromPem(privPem);
        var pubLoaded = RSA.Create(); pubLoaded.ImportFromPem(pubPem);
        return (privLoaded, pubLoaded);
    }

    private static string ExportPrivatePem(RSA rsa)
        => Pem("RSA PRIVATE KEY", rsa.ExportRSAPrivateKey());

    private static string ExportPublicPem(RSA rsa)
        => Pem("PUBLIC KEY", rsa.ExportSubjectPublicKeyInfo());

    private static string Pem(string label, byte[] der)
    {
        var base64 = Convert.ToBase64String(der);
        return $"-----BEGIN {label}-----\n{Chunk(base64, 64)}\n-----END {label}-----\n";
    }

    private static string Chunk(string s, int size)
        => string.Join("\n", Enumerable.Range(0, (s.Length + size - 1) / size)
            .Select(i => s.Substring(i * size, Math.min(size, s.Length - i * size))));
}

file static class Math
{
    public static int min(int a, int b) => a < b ? a : b;
}
