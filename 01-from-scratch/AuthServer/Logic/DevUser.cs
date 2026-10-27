using AuthServer.Infrastructure;
using Microsoft.EntityFrameworkCore;

namespace AuthServer.Logic;

public static class DevUser
{
    public static async Task<Guid> GetAliceId(AuthDbContext db)
    {
        var alice = await db.ResourceOwners.AsNoTracking().FirstAsync(u => u.Username == "alice");
        return alice.Id;
    }
}
