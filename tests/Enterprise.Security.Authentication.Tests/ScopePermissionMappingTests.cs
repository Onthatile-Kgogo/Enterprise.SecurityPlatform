using System.Security.Claims;
using Enterprise.Security.Authentication.Claims;
using Enterprise.Security.Core.Claims;

namespace Enterprise.Security.Authentication.Tests;

public sealed class ScopePermissionMappingTests
{
    [Fact]
    public void Normalize_MapsOnlyExplicitlyConfiguredScopes()
    {
        var user = CreateUser(new Claim("scope", "transactions.manage transactions.delete"));
        var mappings = new Dictionary<string, List<string>>
        {
            ["transactions.manage"] = ["transactions.read", "transactions.write"]
        };

        PermissionClaimsNormalizer.Normalize(user, "permission", "scope", mappings);

        Assert.Equal(
            new[] { "transactions.read", "transactions.write" },
            GetPermissions(user));
    }

    [Fact]
    public void Normalize_SupportsRepeatedScopeClaimsAndCustomClaimType()
    {
        var user = CreateUser(
            new Claim("scp", "read"),
            new Claim("scp", "write"));

        var mappings = new Dictionary<string, List<string>>
        {
            ["read"] = ["transactions.read"],
            ["write"] = ["transactions.write"]
        };

        PermissionClaimsNormalizer.Normalize(
            user, "permission", "scp", mappings);

        Assert.Equal(
            new[] { "transactions.read", "transactions.write" },
            GetPermissions(user));
    }

    [Fact]
    public void Normalize_MatchesScopesCaseSensitively()
    {
        var user = CreateUser(new Claim("scope", "READ"));

        var mappings = new Dictionary<string, List<string>>(
            StringComparer.OrdinalIgnoreCase)
        {
            ["read"] = ["transactions.read"]
        };

        PermissionClaimsNormalizer.Normalize(
            user, "permission", "scope", mappings);

        Assert.Empty(GetPermissions(user));
    }

    [Fact]
    public void Normalize_CombinesDirectAndMappedPermissionsWithoutDuplicates()
    {
        var user = CreateUser(
            new Claim("permission", "transactions.read"),
            new Claim("scope", "manage manage"));

        var mappings = new Dictionary<string, List<string>>
        {
            ["manage"] = ["transactions.read", "transactions.write"]
        };

        PermissionClaimsNormalizer.Normalize(
            user, "permission", "scope", mappings);

        Assert.Equal(
            new[] { "transactions.read", "transactions.write" },
            GetPermissions(user));
    }

    [Fact]
    public void Normalize_DoesNotMapScopesFromUnauthenticatedIdentity()
    {
        var user = CreateUser();

        user.AddIdentity(new ClaimsIdentity([new Claim("scope", "manage")]));

        var mappings = new Dictionary<string, List<string>>
        {
            ["manage"] = ["transactions.write"]
        };

        PermissionClaimsNormalizer.Normalize(user, "permission", "scope", mappings);

        Assert.Empty(GetPermissions(user));
    }

    [Fact]
    public void Normalize_EmptyMappingsGrantNoScopePermissions()
    {
        var user = CreateUser(new Claim("scope", "transactions.read"));

        PermissionClaimsNormalizer.Normalize(
            user,
            "permission",
            "scope",
            new Dictionary<string, List<string>>());

        Assert.Empty(GetPermissions(user));
    }

    private static ClaimsPrincipal CreateUser(params Claim[] claims)
    {
        return new ClaimsPrincipal(
            new ClaimsIdentity(claims, "Test"));
    }

    private static string[] GetPermissions(ClaimsPrincipal user)
    {
        return user.Claims
            .Where(claim => claim.Type == SecurityClaimTypes.Permission)
            .Select(claim => claim.Value)
            .OrderBy(value => value, StringComparer.Ordinal)
            .ToArray();
    }
}