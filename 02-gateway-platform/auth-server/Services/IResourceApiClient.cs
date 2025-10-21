namespace AuthServer.Services
{
    public interface IResourceApiClient
    {
        Task<(bool ok, Guid? onboardId)> VerifyOnboardeeAsync(string lastName, DateOnly birthDate, string? onboardId, CancellationToken ct);
    }
}
