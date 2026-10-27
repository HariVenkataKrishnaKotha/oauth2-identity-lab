using AuthServer.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using StackExchange.Redis;
using System;
using System.ComponentModel;
using System.Diagnostics.Metrics;
using System.Reflection.PortableExecutable;
using System.Runtime.Intrinsics.X86;
using System.Security.Claims;

namespace AuthServer.Pages.Account;

[Authorize] // Must arrive signed in from magic link
public class EnrollModel : PageModel
{
    private readonly UserManager<ApplicationUser> _users;
    private readonly SignInManager<ApplicationUser> _signIn;
    private readonly ILogger<EnrollModel> _logger;

    public EnrollModel(
        UserManager<ApplicationUser> users,
        SignInManager<ApplicationUser> signIn,
        ILogger<EnrollModel> logger)
    {
        _users = users;
        _signIn = signIn;
        _logger = logger;
    }

    [BindProperty]
    public string Email { get; set; } = "";

    [BindProperty]
    public string Password { get; set; } = "";

    [BindProperty]
    public string? ReturnUrl { get; set; } = "/";

    public string? Error { get; set; }

    public void OnGet(string? returnUrl = "/")
    {
        ReturnUrl = returnUrl;
        _logger.LogInformation("Enrollment page loaded, ReturnUrl={ReturnUrl}", returnUrl);
    }

    public async Task<IActionResult> OnPostAsync()
    {
        _logger.LogInformation("Enrollment POST - Email={Email}, ReturnUrl={ReturnUrl}", Email, ReturnUrl);

        // Validate inputs
        if (string.IsNullOrWhiteSpace(Email))
        {
            Error = "Email is required.";
            return Page();
        }

        if (string.IsNullOrWhiteSpace(Password))
        {
            Error = "Password is required.";
            return Page();
        }

        if (Password.Length < 8)
        {
            Error = "Password must be at least 8 characters.";
            return Page();
        }

        // Get current user from authentication cookie
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId is null)
        {
            _logger.LogWarning("User ID not found in claims");
            return Unauthorized();
        }

        var user = await _users.FindByIdAsync(userId);
        if (user is null)
        {
            _logger.LogWarning("User not found: {UserId}", userId);
            return Unauthorized();
        }

        _logger.LogInformation("Setting email and password for user {UserId}", userId);

        // Update email/username
        user.Email = Email;
        user.UserName = Email;
        user.NormalizedEmail = Email.ToUpperInvariant();
        user.NormalizedUserName = Email.ToUpperInvariant();
        user.EmailConfirmed = true; // Auto-confirm for onboardees

        var updateResult = await _users.UpdateAsync(user);
        if (!updateResult.Succeeded)
        {
            var errors = string.Join("; ", updateResult.Errors.Select(e => e.Description));
            _logger.LogWarning("Failed to update user: {Errors}", errors);
            Error = $"Failed to update account: {errors}";
            return Page();
        }

        // Add password
        var passwordResult = await _users.AddPasswordAsync(user, Password);
        if (!passwordResult.Succeeded)
        {
            var errors = string.Join("; ", passwordResult.Errors.Select(e => e.Description));
            _logger.LogWarning("Failed to set password: {Errors}", errors);
            Error = $"Password error: {errors}";
            return Page();
        }

        _logger.LogInformation("User {UserId} enrolled successfully with email {Email}", userId, Email);

        // Re-issue authentication cookie with updated claims
        await _signIn.RefreshSignInAsync(user);

        // Redirect to the OAuth authorize endpoint that was stored in ReturnUrl
        // The ReturnUrl should already be the full OAuth URL from the magic link
        if (string.IsNullOrEmpty(ReturnUrl) || ReturnUrl == "/")
        {
            _logger.LogWarning("ReturnUrl is empty or root, this shouldn't happen");
            return Redirect("/");
        }

        _logger.LogInformation("Redirecting to OAuth authorize: {ReturnUrl}", ReturnUrl);
        return Redirect(ReturnUrl);
    }
}