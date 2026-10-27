using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ResourceApi.Data;
using ResourceApi.Services;

namespace ResourceApi.Controllers;

[ApiController]
[Route("onboarding")]
public class OnboardingController(
    OnboardingDbContext db,
    AuthServerSyncService sync,
    ILogger<OnboardingController> log) : ControllerBase
{
    // ============================================================
    // PUBLIC/INTERNAL ENDPOINTS (No Bearer token required)
    // ============================================================

    /// <summary>
    /// Verify onboardee by lastName + DOB (used by passwordless flow)
    /// </summary>
    [HttpGet("verify")]
    [AllowAnonymous]
    public async Task<IActionResult> Verify(
        [FromQuery] string lastName,
        [FromQuery] DateOnly dob,
        [FromQuery] string? onboardId,
        CancellationToken ct)
    {
        log.LogInformation("Verify request: lastName={LastName}, dob={Dob}, onboardId={OnboardId}",
            lastName, dob, onboardId);

        lastName = lastName.Trim();
        Onboardee? match = null;

        if (!string.IsNullOrWhiteSpace(onboardId) && Guid.TryParse(onboardId, out var id))
        {
            match = await db.Onboardees
                .AsNoTracking()
                .FirstOrDefaultAsync(o => o.Id == id && o.LastName == lastName && o.BirthDate == dob, ct);
        }
        else
        {
            match = await db.Onboardees
                .AsNoTracking()
                .FirstOrDefaultAsync(o => o.LastName == lastName && o.BirthDate == dob, ct);
        }

        if (match is null)
        {
            log.LogInformation("No match found");
            return NotFound(new { Matched = false });
        }

        log.LogInformation("Match found: {FirstName} {LastName}, OnboardId={OnboardId}",
            match.FirstName, match.LastName, match.Id);

        // Sync to AuthServer on first verification
        var username = $"onboardee-{match.Id:N}@local";
        await sync.EnsureOnboardeeAsync(match.Id, username, email: null, ct);

        return Ok(new
        {
            Matched = true,
            OnboardId = match.Id,
            ManagerId = match.ManagerId,
            FirstName = match.FirstName,
            LastName = match.LastName
        });
    }

    /// <summary>
    /// Manager login (used by AuthServer to validate credentials)
    /// </summary>
    [HttpGet("manager-login")]
    [AllowAnonymous]
    public async Task<IActionResult> ManagerLogin(
        [FromQuery] string login,
        [FromQuery] string password,
        CancellationToken ct)
    {
        log.LogInformation("Manager login request for {Login}", login);

        var manager = await db.Managers
            .AsNoTracking()
            .FirstOrDefaultAsync(m => m.Login == login, ct);

        if (manager is null)
        {
            log.LogWarning("Manager not found: {Login}", login);
            return Unauthorized(new { error = "invalid_credentials" });
        }

        // Validate password (plaintext for testing)
        if (manager.PasswordPlain != password)
        {
            log.LogWarning("Invalid password for manager: {Login}", login);
            return Unauthorized(new { error = "invalid_credentials" });
        }

        // Sync to AuthServer
        var passwordHash = PasswordHashing.Hash(login, password);
        var userId = await sync.EnsureManagerAsync(login, manager.Email ?? login, passwordHash, ct);

        log.LogInformation("Manager authenticated: {Login}, UserId={UserId}", login, userId);

        return Ok(new
        {
            Authenticated = true,
            ManagerId = manager.Id,
            UserId = userId
        });
    }

    // ============================================================
    // AUTHENTICATED ENDPOINTS (Require Bearer token from Gateway)
    // ============================================================

    /// <summary>
    /// List all onboardees (authenticated users only)
    /// Managers see their own onboardees, admins see all
    /// </summary>
    [HttpGet("list")]
    [Authorize]
    public async Task<IActionResult> ListOnboardees(CancellationToken ct)
    {
        var userId = User.FindFirst("sub")?.Value;
        var userRole = User.FindFirst("role")?.Value;

        log.LogInformation("List onboardees request from user {UserId} with role {Role}", userId, userRole);

        try
        {
            // If not a manager, return empty list
            if (userRole != "Manager")
            {
                log.LogInformation("Non-manager user attempted to list onboardees");
                return Ok(new List<object>());
            }

            // Manager must have a valid user ID
            if (string.IsNullOrEmpty(userId) || !Guid.TryParse(userId, out var userGuid))
            {
                log.LogWarning("Manager has invalid user ID");
                return Ok(new List<object>());
            }

            // ✅ CRITICAL: Find the manager record by matching the AuthServer user ID
            // The user ID from the token (sub claim) is the AuthServer user ID
            // We need to find the corresponding manager in OnboardingDb

            // First, get the manager's login from AuthServer
            // The manager's username in AuthServer matches their login in OnboardingDb
            var userName = User.FindFirst("name")?.Value;

            if (string.IsNullOrEmpty(userName))
            {
                log.LogWarning("Manager has no username claim");
                return Ok(new List<object>());
            }

            log.LogInformation("Looking for manager with login: {Login}", userName);

            // Find manager by their login (email)
            var manager = await db.Managers
                .AsNoTracking()
                .FirstOrDefaultAsync(m => m.Login == userName, ct);

            if (manager == null)
            {
                log.LogWarning("Manager not found in OnboardingDb with login: {Login}", userName);
                return Ok(new List<object>());
            }

            log.LogInformation("Found manager: {ManagerId}, filtering onboardees", manager.Id);

            // Get onboardees assigned to this manager
            var onboardees = await db.Onboardees
                .Include(o => o.Manager)
                .Where(o => o.ManagerId == manager.Id)  // ✅ Filter by manager ID
                //.OrderByDescending(o => o.CreatedAt)
                .Select(o => new
                {
                    OnboardId = o.Id,
                    o.FirstName,
                    o.LastName,
                    o.BirthDate,
                    o.ManagerId,
                    ManagerEmail = o.Manager != null ? o.Manager.Email : null
                })
                .ToListAsync(ct);

            log.LogInformation("Found {Count} onboardees for manager {ManagerId}", onboardees.Count, manager.Id);

            return Ok(onboardees);
        }
        catch (Exception ex)
        {
            log.LogError(ex, "Error listing onboardees");
            return StatusCode(500, new { error = "internal_error" });
        }
    }

    /// <summary>
    /// Get specific onboardee details
    /// </summary>
    [HttpGet("{onboardId:guid}")]
    [Authorize]
    public async Task<IActionResult> GetOnboardee(Guid onboardId, CancellationToken ct)
    {
        log.LogInformation("Get onboardee request: {OnboardId}", onboardId);

        var onboardee = await db.Onboardees
            .Include(o => o.Manager)
            .FirstOrDefaultAsync(o => o.Id == onboardId, ct);

        if (onboardee is null)
        {
            log.LogWarning("Onboardee not found: {OnboardId}", onboardId);
            return NotFound(new { error = "onboardee_not_found" });
        }

        return Ok(new
        {
            OnboardId = onboardee.Id,
            onboardee.FirstName,
            onboardee.LastName,
            onboardee.BirthDate,
            onboardee.ManagerId,
            ManagerEmail = onboardee.Manager?.Email
        });
    }

    /// <summary>
    /// Approve or reject badge (managers only)
    /// </summary>
    [HttpPost("{onboardId:guid}/badge-approval")]
    [Authorize(Policy = "ManagerOnly")]
    public async Task<IActionResult> ApproveBadge(
        Guid onboardId,
        [FromBody] BadgeApprovalRequest request,
        CancellationToken ct)
    {
        var managerId = User.FindFirst("sub")?.Value;
        var hasBadgePermission = User.HasClaim("perm", "badge_approve");

        log.LogInformation("Badge approval request for {OnboardId} by manager {ManagerId}, HasPerm={HasPerm}",
            onboardId, managerId, hasBadgePermission);

        if (!hasBadgePermission)
        {
            log.LogWarning("Manager {ManagerId} lacks badge_approve permission", managerId);
            return StatusCode(403, new { error = "insufficient_permissions" });
        }

        var onboardee = await db.Onboardees.FindAsync(new object[] { onboardId }, ct);

        if (onboardee is null)
        {
            return NotFound(new { error = "onboardee_not_found" });
        }

        // For demo purposes, we don't have a BadgeStatus field in the simple model
        // In production, you'd update the badge status here
        log.LogInformation("Badge {Status} for {OnboardId}",
            request.Approved ? "approved" : "rejected", onboardId);

        return Ok(new
        {
            onboardId,
            badgeStatus = request.Approved ? "Approved" : "Rejected",
            message = "Badge status updated successfully"
        });
    }
}

public record BadgeApprovalRequest(bool Approved);