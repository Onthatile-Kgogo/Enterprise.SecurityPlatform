using Enterprise.Security.Authorization.Requirements;
using Enterprise.Security.Core.Claims;
using Microsoft.AspNetCore.Authorization;

namespace Enterprise.Security.Authorization.Handlers;

public sealed class PermissionHandler : AuthorizationHandler<PermissionRequirement>
{
    public const string PermissionClaimType = SecurityClaimTypes.Permission;

    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, PermissionRequirement requirement)
    {
        var permissions = context.User.Identities
            .Where(identity => identity.IsAuthenticated)
            .SelectMany(identity => identity.Claims)
            .Where(claim => string.Equals(
                claim.Type,
                PermissionClaimType,
                StringComparison.Ordinal))
            .Select(claim => claim.Value)
            .ToHashSet(StringComparer.Ordinal);

        if (requirement.RequiredPermissions.All(permissions.Contains))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}