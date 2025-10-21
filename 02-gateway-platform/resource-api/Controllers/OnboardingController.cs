using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ResourceApi.Data;
using ResourceApi.Services;

namespace ResourceApi.Controllers;

[ApiController]
[Route("onboarding")]
public class OnboardingController(OnboardingDbContext db, AuthServerSyncService sync, ILogger<OnboardingController> log) : ControllerBase
{
    // GET /onboarding/verify?lastName=Johnson&dob=1995-03-12&onboardId=
    [HttpGet("verify")]
    public async Task<IActionResult> Verify([FromQuery] string lastName, [FromQuery] DateOnly dob, [FromQuery] string? onboardId, CancellationToken ct)
    {
        lastName = lastName.Trim();

        Onboardee? match = null;
        if (!string.IsNullOrWhiteSpace(onboardId) && Guid.TryParse(onboardId, out var id))
        {
            match = await db.Onboardees.AsNoTracking().FirstOrDefaultAsync(o => o.Id == id && o.LastName == lastName && o.BirthDate == dob, ct);
        }
        else
        {
            match = await db.Onboardees.AsNoTracking().FirstOrDefaultAsync(o => o.LastName == lastName && o.BirthDate == dob, ct);
        }

        if (match is null)
            return NotFound(new { Matched = false });

        // FIRST-TIME DUPLICATION into AuthServerDB: ensure User + Onboardee role
        var username = $"onboardee-{match.Id:N}@local";
        await sync.EnsureOnboardeeAsync(match.Id, username, email: null, ct);

        return Ok(new { Matched = true, OnboardId = match.Id, ManagerId = match.ManagerId });
    }
}
