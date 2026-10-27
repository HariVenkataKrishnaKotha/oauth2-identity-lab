using Microsoft.AspNetCore.Identity;

namespace ResourceApi.Services;

// Lightweight Identity user stand-in to compute a valid PasswordHash
public sealed class PasswordUser { public string? UserName { get; set; } }

public static class PasswordHashing
{
    private static readonly PasswordHasher<PasswordUser> _hasher = new();

    public static string Hash(string userName, string plain)
    {
        var u = new PasswordUser { UserName = userName };
        return _hasher.HashPassword(u, plain);
    }
}
