using AuthServer.Contracts;
using AuthServer.Identity;
using AuthServer.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using StackExchange.Redis;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;

namespace AuthServer.Controllers;

[ApiController]
[Route("onboarding")]
public class OnboardingController : ControllerBase
{
    private readonly IResourceApiClient _resourceApi;
    private readonly IMagicLinkService _magic;
    private readonly UserManager<ApplicationUser> _users;
    private readonly IConnectionMultiplexer _mux;

    public OnboardingController(IResourceApiClient resourceApi, IMagicLinkService magic, UserManager<ApplicationUser> users, IConnectionMultiplexer mux)
    {
        _resourceApi = resourceApi;
        _magic = magic;
        _users = users;
        _mux = mux;
    }

    // Step 1: Identify (Lastname + DOB) — verify against SAP via Resource API
    [HttpPost("identify")]
    [ProducesResponseType(typeof(IdentifyResponse), 200)]
    public async Task<IActionResult> Identify([FromBody] IdentifyRequest req, CancellationToken ct)
    {
        // Basic per-IP rate limit via Redis
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var db = _mux.GetDatabase();
        var rlKey = RedisKeys.IdentifyRate(ip);
        var count = await db.StringIncrementAsync(rlKey);
        if (count == 1) await db.KeyExpireAsync(rlKey, TimeSpan.FromMinutes(5)); // window
        if (count > 20) return StatusCode((int)HttpStatusCode.TooManyRequests, new { error = "rate_limited" });

        var (ok, onboardId) = await _resourceApi.VerifyOnboardeeAsync(req.LastName.Trim(), req.BirthDate, req.OnboardId, ct);
        if (!ok || onboardId is null) return Unauthorized(new { error = "not_found" });

        // Upsert a temp user; we’ll formalize on redemption
        var tempUser = await _users.FindByIdAsync(onboardId.Value.ToString());
        if (tempUser is null)
        {
            tempUser = new ApplicationUser
            {
                Id = onboardId.Value,
                UserName = $"onboardee-{onboardId.Value:N}@local",
                Email = null,
                OnboardId = onboardId.Value
            };
            await _users.CreateAsync(tempUser);
            await _users.AddToRoleAsync(tempUser, "Onboardee");
        }

        // Create a verify session (one-time) and a magic link you can email/SMS
        var verifyId = await _magic.CreateVerifySessionAsync(tempUser.Id, TimeSpan.FromMinutes(10), ct);
        var link = $"https://auth.local/onboarding/magic?vs={Uri.EscapeDataString(verifyId)}"; // behind gateway in prod

        // TODO: send link by email or SMS based on your delivery strategy.
        return Ok(new IdentifyResponse(verifyId, "link", DateTimeOffset.UtcNow.AddMinutes(10)));
    }

    // Step 2a: Magic link redemption (GET from email/SMS)
    [HttpGet("magic")]
    public async Task<IActionResult> Magic([FromQuery] string vs, [FromQuery] string? redirect, CancellationToken ct)
    {
        var (ok, tempUserId) = await _magic.RedeemAsync(vs, ct);
        if (!ok) return Unauthorized("expired_or_invalid");

        var user = await _users.FindByIdAsync(tempUserId.ToString());
        if (user is null) return Unauthorized("user_missing");

        // Sign them into the server (cookie), then bounce through /connect/authorize
        await HttpContext.SignInAsync(
            IdentityConstants.ApplicationScheme,
            await BuildIdentityCookiePrincipalAsync(user),
            new AuthenticationProperties { IsPersistent = false });

        // On first time, force enrollment
        var enrollUrl = Url.Page("/Account/Enroll", new { returnUrl = redirect });
        return Redirect(enrollUrl!);
    }

    // Step 2b: Alternative — code verification post (if you choose OTP)
    [HttpPost("verify-code")]
    public async Task<IActionResult> VerifyCode([FromBody] VerifyCodeRequest req, CancellationToken ct)
    {
        // If you implement numeric OTP, put its validation here (stored in Redis like verify session).
        return BadRequest(new { error = "not_implemented" });
    }

    // Build cookie principal with minimal claims
    private async Task<ClaimsPrincipal> BuildIdentityCookiePrincipalAsync(ApplicationUser user)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Name, user.UserName ?? $"onboardee-{user.Id:N}"),
            new("onboard_id", user.OnboardId?.ToString() ?? "")
        };

        var roles = await _users.GetRolesAsync(user);
        claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));

        var identity = new ClaimsIdentity(claims, IdentityConstants.ApplicationScheme);
        return new ClaimsPrincipal(identity);
    }
}
