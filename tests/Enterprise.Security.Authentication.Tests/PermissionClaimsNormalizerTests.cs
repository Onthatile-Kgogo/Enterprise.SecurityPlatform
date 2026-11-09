using System.Security.Claims;
using Enterprise.Security.Authentication.Claims;
using Enterprise.Security.Core.Claims;

namespace Enterprise.Security.Authentication.Tests;

public sealed class PermissionClaimsNormalizerTests
{
    [Fact]
    public void Normalize_MapsConfiguredPermissionClaims()
    {
        var user = CreateUser(
            new Claim("permissions", "transactions.read"),
            new Claim("permissions", "transactions.write"),
            new Claim("permission", "transactions.delete"));

        PermissionClaimsNormalizer.Normalize(user, "permissions");

        Assert.Equal(
            new[] { "transactions.read", "transactions.write" },
            GetPermissions(user));
    }

    [Fact]
    public void Normalize_RemovesIncomingInternalPermissionClaims()
    {
        var user = CreateUser(
            new Claim(SecurityClaimTypes.Permission, "transactions.delete"),
            new Claim(                SecurityClaimTypes.Permission.ToUpperInvariant(),                "transactions.approve"),
            new Claim("permissions", "transactions.read"));

        PermissionClaimsNormalizer.Normalize(user, "permissions");

        Assert.Equal(            new[] { "transactions.read" },            GetPermissions(user));

        Assert.DoesNotContain(user.Claims, claim =>
            claim.Value == "transactions.delete" ||
            claim.Value == "transactions.approve");
    }

    [Fact]
    public void Normalize_IgnoresUnauthenticatedIdentities()
    {
        var identity = new ClaimsIdentity(
        [
            new Claim("permissions", "transactions.read"),
            new Claim(SecurityClaimTypes.Permission, "transactions.delete")
        ]);

        var user = new ClaimsPrincipal(identity);

        PermissionClaimsNormalizer.Normalize(user, "permissions");

        Assert.Empty(GetPermissions(user));
    }

    [Fact]
    public void Normalize_DoesNotMapRawScopes()
    {
        var user = CreateUser(
            new Claim("scope", "transactions.read transactions.write"));

        PermissionClaimsNormalizer.Normalize(user, "permissions");

        Assert.Empty(GetPermissions(user));
    }

    [Fact]
    public void Normalize_RemovesDuplicateAndBlankPermissions()
    {
        var user = CreateUser(
            new Claim("permissions", "transactions.read"),
            new Claim("permissions", "transactions.read"),
            new Claim("permissions", ""),
            new Claim("permissions", " "));

        PermissionClaimsNormalizer.Normalize(user, "permissions");

        Assert.Equal(
            new[] { "transactions.read" },
            GetPermissions(user));
    }

    [Fact]
    public void Normalize_CanRunTwiceWithoutDuplicatingPermissions()
    {
        var user = CreateUser(
            new Claim("permissions", "transactions.read"));

        PermissionClaimsNormalizer.Normalize(user, "permissions");
        PermissionClaimsNormalizer.Normalize(user, "permissions");

        Assert.Equal(
            new[] { "transactions.read" },
            GetPermissions(user));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("enterprise_security_permission")]
    [InlineData("ENTERPRISE_SECURITY_PERMISSION")]
    public void Normalize_RejectsInvalidOrReservedClaimType(
        string claimType)
    {
        var user = CreateUser();

        Assert.Throws<ArgumentException>(() =>
            PermissionClaimsNormalizer.Normalize(user, claimType));
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