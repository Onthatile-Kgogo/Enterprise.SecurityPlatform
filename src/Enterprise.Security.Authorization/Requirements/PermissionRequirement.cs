using Microsoft.AspNetCore.Authorization;

namespace Enterprise.Security.Authorization.Requirements;

public sealed class PermissionRequirement : IAuthorizationRequirement
{
    public IReadOnlyList<string> RequiredPermissions { get; }

    public PermissionRequirement(IEnumerable<string> requiredPermissions)
    {
        ArgumentNullException.ThrowIfNull(requiredPermissions);

        var permissions = requiredPermissions.ToArray();
        if (permissions.Length == 0 || permissions.Any(string.IsNullOrWhiteSpace))
        {
            throw new ArgumentException("At least one non-empty permission is required.", nameof(requiredPermissions));
        }
        RequiredPermissions = Array.AsReadOnly(permissions);
    }
}