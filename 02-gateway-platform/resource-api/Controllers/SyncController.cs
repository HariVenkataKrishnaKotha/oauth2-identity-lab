using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ResourceApi.Data;
using ResourceApi.Services;

namespace ResourceApi.Controllers;

[ApiController]
[Route("internal/sync")]
public class SyncController(OnboardingDbContext db, AuthServerSyncService sync, ILogger<SyncController> log) : ControllerBase
{
    // POST /internal/sync/manager  { "login":"manager1@example.com", "password":"P@ssw0rd!123" }
    public record ManagerLoginDto(string Login, string Password);

    [HttpPost("manager")]
    public async Task<IActionResult> SyncManager([FromBody] ManagerLoginDto dto, CancellationToken ct)
    {
        var m = await db.Managers.AsNoTracking().FirstOrDefaultAsync(x => x.Login == dto.Login, ct);
        if (m is null) return Unauthorized(new { error = "manager_not_found" });

        // Validate against OnboardingDb (plaintext for test purposes)
        if (!string.Equals(dto.Password, m.PasswordPlain))
            return Unauthorized(new { error = "invalid_credentials" });

        var pwdHash = PasswordHashing.Hash(m.Login, dto.Password);
        var userId = await sync.EnsureManagerAsync(m.Login, m.Email ?? m.Login, pwdHash, ct);
        return Ok(new { Synced = true, UserId = userId });
    }
}
