namespace Enterprise.Security.Core.Configuration.JwtConfig
{
    public sealed class JwtProviderOptions
    {
        public string Scheme { get; set; } = string.Empty;
        public string Authority { get; set; } = string.Empty;
        public string Audience { get; set; } = string.Empty;
        public bool RequireHttpsMetadata { get; set; } = true;
        public string RoleClaimType { get; set; } = "role";
        public string PermissionClaimType { get; set; } = "permission";
    }
}
