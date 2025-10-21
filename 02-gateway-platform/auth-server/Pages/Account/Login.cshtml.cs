using AuthServer.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AuthServer.Pages.Account;

public class LoginModel : PageModel
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;

    public LoginModel(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager)
    {
        _signInManager = signInManager;
        _userManager = userManager;
    }

    [BindProperty] public string Email { get; set; } = string.Empty;
    [BindProperty] public string Password { get; set; } = string.Empty;
    [BindProperty] public string? ReturnUrl { get; set; } = "/";
    public string? Error { get; set; }

    public void OnGet(string? returnUrl = "/") => ReturnUrl = returnUrl;

    public async Task<IActionResult> OnPost()
    {
        var user = await _userManager.FindByEmailAsync(Email);
        if (user is null)
        {
            Error = "Invalid credentials.";
            return Page();
        }

        var result = await _signInManager.PasswordSignInAsync(user, Password, isPersistent: false, lockoutOnFailure: true);
        if (!result.Succeeded)
        {
            Error = result.IsLockedOut ? "Account locked." : "Invalid credentials.";
            return Page();
        }

        if (!string.IsNullOrEmpty(ReturnUrl) && Url.IsLocalUrl(ReturnUrl))
            return LocalRedirect(ReturnUrl);

        return Redirect("~/");
    }
}
