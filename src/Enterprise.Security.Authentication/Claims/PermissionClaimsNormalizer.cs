using System.Security.Claims;
using Enterprise.Security.Core.Claims;

namespace Enterprise.Security.Authentication.Claims;

public static class PermissionClaimsNormalizer
{
    public static void Normalize(ClaimsPrincipal principal, string permissionClaimType, string scopeClaimType = "scope", IReadOnlyDictionary<string, List<string>>? scopeToPermissions = null)
    {
        ArgumentNullException.ThrowIfNull(principal);

        ValidateClaimType(permissionClaimType, nameof(permissionClaimType));
        ValidateClaimType(scopeClaimType, nameof(scopeClaimType));

        // Enforce exact scope matching regardless of the supplied comparer.
        var mappings = scopeToPermissions?.ToDictionary(
            entry => entry.Key,
            entry => entry.Value,
            StringComparer.Ordinal);

        foreach (var identity in principal.Identities)
        {
            var existingClaims = identity.Claims
                .Where(claim => string.Equals(
                    claim.Type,
                    SecurityClaimTypes.Permission,
                    StringComparison.OrdinalIgnoreCase))
                .ToArray();

            foreach (var claim in existingClaims)
                identity.RemoveClaim(claim);

            if (!identity.IsAuthenticated)
                continue;

            var permissions = identity.Claims
                .Where(claim => string.Equals(
                    claim.Type,
                    permissionClaimType,
                    StringComparison.Ordinal))
                .Select(claim => claim.Value)
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .ToHashSet(StringComparer.Ordinal);

            if (mappings is not null && mappings.Count > 0)
            {
                var scopes = identity.Claims
                    .Where(claim => string.Equals(
                        claim.Type,
                        scopeClaimType,
                        StringComparison.Ordinal))
                    .SelectMany(claim => claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries));

                foreach (var scope in scopes)
                {
                    if (!mappings.TryGetValue(scope, out var mappedPermissions))
                        continue;

                    foreach (var permission in mappedPermissions)
                    {
                        if (!string.IsNullOrWhiteSpace(permission))
                            permissions.Add(permission);
                    }
                }
            }

            foreach (var permission in permissions)
            {
                identity.AddClaim(new Claim(SecurityClaimTypes.Permission, permission));
            }
        }
    }

    private static void ValidateClaimType(string claimType, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(claimType) || string.Equals(claimType, SecurityClaimTypes.Permission, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("A non-reserved provider claim type is required.", parameterName);
        }
    }
}