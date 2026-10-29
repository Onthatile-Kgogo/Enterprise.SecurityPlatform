namespace Enterprise.Security.Core.Configuration.AuthorizationConfig
{
    public sealed class AuthorizationPolicyOptions
    {
        public List<string> RequiredPermissions { get; set; } = [];
        public List<List<string>> RoleGroups { get; set; } = [];
        public List<string> RequiredPolicies { get; set; } = [];
    }
}
