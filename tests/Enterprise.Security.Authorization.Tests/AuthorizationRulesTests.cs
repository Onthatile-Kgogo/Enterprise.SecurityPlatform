using System.Security.Claims;
using Enterprise.Security.Authorization.Handlers;
using Enterprise.Security.Authorization.Requirements;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;

namespace Enterprise.Security.Authorization.Tests;

public sealed class AuthorizationRulesTests
{
    private const string PermissionClaimType =
        "enterprise_security_permission";

    [Theory]
    [InlineData(true, true, true)]
    [InlineData(true, false, false)]
    [InlineData(false, true, false)]
    [InlineData(false, false, false)]
    public async Task Permissions_RequireEveryListedPermission(
        bool hasRead,
        bool hasWrite,
        bool expected)
    {
        var claims = new List<Claim>();

        if (hasRead)
            claims.Add(new Claim(PermissionClaimType, "transactions.read"));

        if (hasWrite)
            claims.Add(new Claim(PermissionClaimType, "transactions.write"));

        var policy = new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .AddRequirements(new PermissionRequirement(
                ["transactions.read", "transactions.write"]))
            .Build();

        var result = await EvaluateAsync(CreateUser(claims), policy);

        Assert.Equal(expected, result.Succeeded);
    }

    [Fact]
    public async Task Permissions_RejectUnauthenticatedIdentity()
    {
        var user = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(PermissionClaimType, "transactions.read")]));

        var policy = new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .AddRequirements(new PermissionRequirement(
                ["transactions.read"]))
            .Build();

        var result = await EvaluateAsync(user, policy);

        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task Permissions_IgnoreClaimsFromUnauthenticatedIdentity()
    {
        var user = CreateUser([]);

        user.AddIdentity(new ClaimsIdentity(
            [new Claim(PermissionClaimType, "transactions.read")]));

        var policy = new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .AddRequirements(new PermissionRequirement(
                ["transactions.read"]))
            .Build();

        var result = await EvaluateAsync(user, policy);

        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task Permissions_DoNotTreatRawScopeAsPermission()
    {
        var user = CreateUser(
            [new Claim("scope", "transactions.read")]);

        var policy = new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .AddRequirements(new PermissionRequirement(
                ["transactions.read"]))
            .Build();

        var result = await EvaluateAsync(user, policy);

        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task Permissions_RequireExactValueMatch()
    {
        var user = CreateUser(
            [new Claim(PermissionClaimType, "Transactions.Read")]);

        var policy = new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .AddRequirements(new PermissionRequirement(
                ["transactions.read"]))
            .Build();

        var result = await EvaluateAsync(user, policy);

        Assert.False(result.Succeeded);
    }

    [Theory]
    [InlineData("Admin", true)]
    [InlineData("Operator", true)]
    [InlineData("Viewer", false)]
    public async Task RoleGroup_AcceptsAnyListedRole(
        string role,
        bool expected)
    {
        var user = CreateUser([new Claim("roles", role)]);

        var policy = new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .RequireRole("Admin", "Operator")
            .Build();

        var result = await EvaluateAsync(user, policy);

        Assert.Equal(expected, result.Succeeded);
    }

    [Theory]
    [InlineData(true, true, true)]
    [InlineData(true, false, false)]
    [InlineData(false, true, false)]
    [InlineData(false, false, false)]
    public async Task RoleGroupsAndPermissions_MustAllPass(
        bool hasSecondRoleGroup,
        bool hasPermission,
        bool expected)
    {
        var claims = new List<Claim>
        {
            new("roles", "Operator")
        };

        if (hasSecondRoleGroup)
            claims.Add(new Claim("roles", "Approver"));

        if (hasPermission)
            claims.Add(new Claim(
                PermissionClaimType, "transactions.approve"));

        var policy = new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .RequireRole("Admin", "Operator")
            .RequireRole("Approver", "Supervisor")
            .AddRequirements(new PermissionRequirement(
                ["transactions.approve"]))
            .Build();

        var result = await EvaluateAsync(CreateUser(claims), policy);

        Assert.Equal(expected, result.Succeeded);
    }

    private static ClaimsPrincipal CreateUser(IEnumerable<Claim> claims)
    {
        return new ClaimsPrincipal(new ClaimsIdentity(
            claims,
            authenticationType: "Test",
            nameType: ClaimTypes.Name,
            roleType: "roles"));
    }

    private static async Task<AuthorizationResult> EvaluateAsync(
        ClaimsPrincipal user,
        AuthorizationPolicy policy)
    {
        var services = new ServiceCollection();

        services.AddLogging();
        services.AddAuthorization();
        services.AddSingleton<IAuthorizationHandler, PermissionHandler>();

        using var provider = services.BuildServiceProvider();

        var authorization =
            provider.GetRequiredService<IAuthorizationService>();

        return await authorization.AuthorizeAsync(user, null, policy);
    }
}