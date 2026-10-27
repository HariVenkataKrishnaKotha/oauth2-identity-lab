using AuthServer.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;

namespace AuthServer.Pages.Account;

[AllowAnonymous]
public class LoginModel : PageModel
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILogger<LoginModel> _logger;
    private readonly IHttpClientFactory _httpClientFactory;

    public LoginModel(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        ILogger<LoginModel> logger,
        IHttpClientFactory httpClientFactory)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _logger = logger;
        _httpClientFactory = httpClientFactory;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public string? ReturnUrl { get; set; }

    public string? ErrorMessage { get; set; }

    public class InputModel
    {
        [Required]
        public string Username { get; set; } = "";

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; } = "";

        public bool RememberMe { get; set; }
    }

    public void OnGet(string? returnUrl = null)
    {
        ReturnUrl = returnUrl;
        _logger.LogInformation("Login page loaded with ReturnUrl: {ReturnUrl}", returnUrl);
    }

    public async Task<IActionResult> OnPostAsync(string? returnUrl = null)
    {
        ReturnUrl = returnUrl;

        _logger.LogInformation("Login POST: Username={Username}, ReturnUrl={ReturnUrl}",
            Input?.Username, returnUrl);

        if (!ModelState.IsValid)
        {
            _logger.LogWarning("ModelState invalid. Errors: {Errors}",
                string.Join(", ", ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage)));
            ErrorMessage = "Please enter both username and password.";
            return Page();
        }

        if (Input == null || string.IsNullOrEmpty(Input.Username) || string.IsNullOrEmpty(Input.Password))
        {
            _logger.LogWarning("Input is null or empty");
            ErrorMessage = "Please enter both username and password.";
            return Page();
        }

        // Try to find user in AuthServerDb
        var user = await _userManager.FindByNameAsync(Input.Username);

        if (user == null)
        {
            _logger.LogInformation("User not found in AuthServerDb, attempting manager sync from ResourceAPI");

            // First-time manager - call ResourceAPI directly
            try
            {
                var httpClient = _httpClientFactory.CreateClient("ResourceApiDirect");
                // Credentials go in the POST body so they never appear in a URL or request log
                _logger.LogInformation("Calling ResourceAPI manager-login for {Username}", Input.Username);

                var response = await httpClient.PostAsJsonAsync(
                    "/onboarding/manager-login",
                    new ManagerLoginRequest(Input.Username, Input.Password));

                if (response.IsSuccessStatusCode)
                {
                    var result = await response.Content.ReadFromJsonAsync<ManagerLoginResult>();

                    if (result?.Authenticated == true && result.UserId.HasValue)
                    {
                        _logger.LogInformation("Manager authenticated via ResourceAPI, UserId: {UserId}", result.UserId);

                        // User was synced, try to find again
                        user = await _userManager.FindByIdAsync(result.UserId.Value.ToString());

                        if (user == null)
                        {
                            _logger.LogError("User synced but not found in database");
                            ErrorMessage = "Authentication error. Please try again.";
                            return Page();
                        }
                    }
                    else
                    {
                        _logger.LogWarning("Manager authentication failed at ResourceAPI");
                        ErrorMessage = "Invalid username or password.";
                        return Page();
                    }
                }
                else
                {
                    _logger.LogWarning("ResourceAPI returned error: {StatusCode}", response.StatusCode);
                    ErrorMessage = "Invalid username or password.";
                    return Page();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error calling ResourceAPI for manager login");
                ErrorMessage = "Authentication service unavailable. Please try again.";
                return Page();
            }
        }

        // Verify password
        var signInResult = await _signInManager.PasswordSignInAsync(user, Input.Password, Input.RememberMe, lockoutOnFailure: false);

        if (signInResult.Succeeded)
        {
            _logger.LogInformation("User {Username} logged in successfully", Input.Username);

            // Redirect to returnUrl
            if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
            {
                _logger.LogInformation("Redirecting to: {ReturnUrl}", returnUrl);
                return LocalRedirect(returnUrl);
            }

            return LocalRedirect("~/");
        }

        _logger.LogWarning("Invalid login attempt for {Username}", Input.Username);
        ErrorMessage = "Invalid username or password.";
        return Page();
    }

    private record ManagerLoginRequest(string Login, string Password);

    private record ManagerLoginResult(bool Authenticated, Guid? UserId, Guid? ManagerId);
}