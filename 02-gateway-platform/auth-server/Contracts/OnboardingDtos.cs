namespace AuthServer.Contracts;

public class IdentifyRequest
{
    public string LastName { get; set; } = "";
    public DateOnly BirthDate { get; set; }
    public string? OnboardId { get; set; }
}

public class IdentifyResponse
{
    public IdentifyResponse(string verifySessionId, string delivery, DateTimeOffset expiresAt)
    {
        VerifySessionId = verifySessionId;
        Delivery = delivery;
        ExpiresAt = expiresAt;
    }
    public string VerifySessionId { get; set; }
    public string Delivery { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
}

public class VerifyCodeRequest
{
    public string VerifySessionId { get; set; } = "";
    public string Code { get; set; } = "";
}

public class MagicLinkPayload
{
    public MagicLinkPayload(string verifySessionId, Guid tempUserId)
    {
        VerifySessionId = verifySessionId;
        TempUserId = tempUserId;
    }
    public string VerifySessionId { get; set; }
    public Guid TempUserId { get; set; }
}
