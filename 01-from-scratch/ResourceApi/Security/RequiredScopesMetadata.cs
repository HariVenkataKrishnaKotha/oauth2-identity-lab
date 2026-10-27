namespace ResourceApi.Security;

public sealed class RequiredScopesMetadata
{
    public string[] Scopes { get; }
    public RequiredScopesMetadata(params string[] scopes) => Scopes = scopes;
}
