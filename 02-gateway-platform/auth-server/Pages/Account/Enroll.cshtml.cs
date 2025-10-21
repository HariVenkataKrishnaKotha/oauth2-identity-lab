using AuthServer.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Claims;

namespace AuthServer.Pages.Account;

[Authorize] // Must arrive signed in from magic link
public class EnrollModel : PageModel
{
    private readonly UserManager<ApplicationUser> _users;
    private readonly SignInManager<ApplicationUser> _signIn;

    public EnrollModel(UserManager<ApplicationUser> users, SignInManager<ApplicationUser> signIn)
    {
        _users = users; _signIn = signIn;
    }

    [BindProperty] public string Email { get; set; } = "";
    [BindProperty] public string Password { get; set; } = "";
    [BindProperty] public string? ReturnUrl { get; set; } = "/";

    public void OnGet(string? returnUrl = "/") => ReturnUrl = returnUrl;

    public async Task<IActionResult> OnPost()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId is null) return Unauthorized();

        var user = await _users.FindByIdAsync(userId);
        if (user is null) return Unauthorized();

        // Bind the chosen email/username + password
        user.Email = Email;
        user.UserName = Email;
        var ures = await _users.UpdateAsync(user);
        if (!ures.Succeeded)
        {
            return PageWithError(string.Join("; ", ures.Errors.Select(e => e.Description)));
        }

        var pres = await _users.AddPasswordAsync(user, Password);
        if (!pres.Succeeded)
        {
            return PageWithError(string.Join("; ", pres.Errors.Select(e => e.Description)));
        }

        // Re-issue cookie with new username/email
        await _signIn.RefreshSignInAsync(user);

        // Now bounce to standard OIDC authorize to mint tokens for the calling app
        // You’ll typically carry original OIDC params via the initial link/state.
        var authorizeUrl = $"/connect/authorize?client_id=nuxt-ssr&response_type=code&redirect_uri={Uri.EscapeDataString(ReturnUrl ?? "/")}&scope=openid%20profile%20email%20onboarding.read%20offline_access&state=st&code_challenge=dev&code_challenge_method=plain";
        return Redirect(authorizeUrl);
    }

    private IActionResult PageWithError(string err) { Error = err; return Page(); }
    public string? Error { get; set; }
}
