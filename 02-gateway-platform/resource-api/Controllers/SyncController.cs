using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ResourceApi.Data;
using ResourceApi.Services;

namespace ResourceApi.Controllers;

[ApiController]
[Route("internal/sync")]
[AllowAnonymous] // Internal endpoints don't require Bearer tokens
public class SyncController(
    OnboardingDbContext db,
    AuthServerSyncService sync,
    ILogger<SyncController> log) : ControllerBase
{
    /// <summary>
    /// Sync manager to AuthServer (called by AuthServer during first login)
    /// </summary>
    [HttpPost("manager")]
    public async Task<IActionResult> SyncManager([FromBody] ManagerLoginDto dto, CancellationToken ct)
    {
        log.LogInformation("Sync manager request for {Login}", dto.Login);

        var m = await db.Managers
            .AsNoTracking()
            .FirstOrDefaultAsync(x => x.Login == dto.Login, ct);

        if (m is null)
        {
            log.LogWarning("Manager not found: {Login}", dto.Login);
            return Unauthorized(new { error = "manager_not_found" });
        }

        // Validate against OnboardingDb (plaintext for test purposes)
        if (!string.Equals(dto.Password, m.PasswordPlain))
        {
            log.LogWarning("Invalid password for manager: {Login}", dto.Login);
            return Unauthorized(new { error = "invalid_credentials" });
        }

        var pwdHash = PasswordHashing.Hash(m.Login, dto.Password);
        var userId = await sync.EnsureManagerAsync(m.Login, m.Email ?? m.Login, pwdHash, ct);

        log.LogInformation("Manager synced: {Login}, UserId={UserId}", m.Login, userId);

        return Ok(new { Synced = true, UserId = userId });
    }

    /// <summary>
    /// Sync onboardee to AuthServer (called during passwordless verification)
    /// </summary>
    [HttpPost("onboardee")]
    public async Task<IActionResult> SyncOnboardee([FromBody] OnboardeeSyncDto dto, CancellationToken ct)
    {
        log.LogInformation("Sync onboardee request for lastName={LastName}, dob={Dob}",
            dto.LastName, dto.BirthDate);

        var onboardee = await db.Onboardees
            .AsNoTracking()
            .FirstOrDefaultAsync(o =>
                o.LastName.Equals(dto.LastName, StringComparison.OrdinalIgnoreCase) &&
                o.BirthDate == dto.BirthDate, ct);

        if (onboardee is null)
        {
            log.LogWarning("Onboardee not found: lastName={LastName}, dob={Dob}",
                dto.LastName, dto.BirthDate);
            return NotFound(new { Synced = false, error = "not_found" });
        }

        var username = $"onboardee-{onboardee.Id:N}@local";
        var userId = await sync.EnsureOnboardeeAsync(onboardee.Id, username, email: null, ct);

        log.LogInformation("Onboardee synced: {FirstName} {LastName}, UserId={UserId}",
            onboardee.FirstName, onboardee.LastName, userId);

        return Ok(new
        {
            Synced = true,
            UserId = userId,
            OnboardId = onboardee.Id,
            FirstName = onboardee.FirstName,
            LastName = onboardee.LastName
        });
    }

    public record ManagerLoginDto(string Login, string Password);
    public record OnboardeeSyncDto(string LastName, DateOnly BirthDate);
}