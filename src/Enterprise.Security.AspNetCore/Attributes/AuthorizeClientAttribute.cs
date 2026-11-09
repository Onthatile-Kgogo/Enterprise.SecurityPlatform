using Enterprise.Security.Authorization.Requirements;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;

namespace Enterprise.Security.AspNetCore.Attributes;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
public sealed class AuthorizeClientAttribute : AuthorizeAttribute, IAuthorizationRequirementData
{
    public string? Permissions { get; set; }

    public IEnumerable<IAuthorizationRequirement> GetRequirements()
    {
        yield return new DenyAnonymousAuthorizationRequirement();

        if (Permissions is null)
            yield break;

        var permissions = Permissions.Split(',', StringSplitOptions.TrimEntries);
        yield return new PermissionRequirement(permissions);
    }
}