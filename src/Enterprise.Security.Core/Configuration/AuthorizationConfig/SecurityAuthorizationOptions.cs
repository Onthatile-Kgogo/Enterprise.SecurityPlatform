namespace Enterprise.Security.Core.Configuration.AuthorizationConfig;

public sealed class SecurityAuthorizationOptions
{
    public const string SectionName = "EnterpriseSecurity:Authorization";
    public bool Enabled { get; set; }
    public bool RequireAuthenticatedUserByDefault { get; set; }
    public Dictionary<string, AuthorizationPolicyOptions> Policies { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}
