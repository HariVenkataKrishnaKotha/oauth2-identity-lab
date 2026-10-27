namespace AuthServer.Services;

public static class RedisKeys
{
    public static string IdentifyRate(string ip) => $"rl:identify:{ip}";
    public static string VerifySession(string id) => $"verifysess:{id}";
}
