namespace Enterprise.Security.Core.Configuration.OAuthConfig
{
    public sealed class OAuthClientOptions
    {
        public string ClientId { get; set; } = string.Empty;
        public string ClientSecret { get; set; } = string.Empty;
        public string TokenEndpoint { get; set; } = string.Empty;
        public string[] Scopes { get; set; } = [];
    }
}
