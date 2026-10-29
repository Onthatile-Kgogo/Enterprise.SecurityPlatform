namespace Enterprise.Security.Core.Configuration.JwtConfig;

public sealed class JwtAuthenticationOptions
{
    public const string SectionName = "EnterpriseSecurity:Authentication";
    public bool Enabled { get; set; }
    public Dictionary<string, JwtProviderOptions> Providers { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}
