using System.Net.Http.Json;

namespace AuthServer.Services;

public sealed class ResourceApiClient(HttpClient http) : IResourceApiClient
{
    public async Task<(bool ok, Guid? onboardId)> VerifyOnboardeeAsync(string lastName, DateOnly birthDate, string? onboardId, CancellationToken ct)
    {
        // Adjust URL to your Resource API (behind the gateway in prod)
        var url = $"https://localhost:5173/onboarding/verify?lastName={Uri.EscapeDataString(lastName)}&dob={birthDate:yyyy-MM-dd}&onboardId={Uri.EscapeDataString(onboardId ?? "")}";
        var resp = await http.GetAsync(url, ct);
        if (!resp.IsSuccessStatusCode) return (false, null);

        var payload = await resp.Content.ReadFromJsonAsync<VerifyDto>(cancellationToken: ct);
        return (payload?.Matched == true, payload?.OnboardId);
    }

    private sealed class VerifyDto
    {
        public bool Matched { get; set; }
        public Guid OnboardId { get; set; }
    }

}
