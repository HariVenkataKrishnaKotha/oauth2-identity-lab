using Microsoft.AspNetCore.Identity;

namespace AuthServer.Identity;

public sealed class ApplicationUser : IdentityUser<Guid>
{
    // Extend as needed (e.g., OnboardId)
    public Guid? OnboardId { get; set; }
}
