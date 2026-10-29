namespace Enterprise.Security.Core.Configuration.OAuthConfig
{
    public sealed class OAuthOptions
    {
        public const string SectionName = "EnterpriseSecurity:OAuth";
        public bool Enabled { get; set; }
        public Dictionary<string, OAuthClientOptions> Clients { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }
}
