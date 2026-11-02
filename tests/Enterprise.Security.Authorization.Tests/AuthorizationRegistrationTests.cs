using System.Security.Claims;
using Enterprise.Security.Authorization.Extensions;
using Enterprise.Security.Core.Configuration.AuthorizationConfig;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Enterprise.Security.Authorization.Tests;

public sealed class AuthorizationRegistrationTests
{
    [Theory]
    [InlineData(true, true, true)]
    [InlineData(true, false, false)]
    [InlineData(false, true, false)]
    [InlineData(false, false, false)]
    public async Task ReferencedPolicies_MustAllPass(        bool hasRole,        bool hasPermission,        bool expected)
    {
        var options = new SecurityAuthorizationOptions
        {
            Enabled = true,
            Policies =
            {
                ["CanRead"] = new()
                {
                    RequiredPermissions = ["transactions.read"]
                },
                ["IsOperator"] = new()
                {
                    RoleGroups = [["Admin", "Operator"]]
                },
                ["ReadTransactions"] = new()
                {
                    RequiredPolicies = ["CanRead", "IsOperator"]
                }
            }
        };

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddEnterpriseAuthorization(options);

        using var provider = services.BuildServiceProvider();

        var claims = new List<Claim>();

        if (hasRole)
            claims.Add(new Claim(ClaimTypes.Role, "Operator"));

        if (hasPermission)
        {
            claims.Add(new Claim(                "enterprise_security_permission",                "transactions.read"));
        }

        var user = new ClaimsPrincipal(            new ClaimsIdentity(claims, "Test"));
        var authorization =            provider.GetRequiredService<IAuthorizationService>();
        var result = await authorization.AuthorizeAsync(            user, null, "ReadTransactions");
        
        Assert.Equal(expected, result.Succeeded);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void GlobalAuthentication_IsControlledByConfiguration(
        bool enabled)
    {
        var services = new ServiceCollection();

        services.AddLogging();
        services.AddEnterpriseAuthorization(
            new SecurityAuthorizationOptions
            {
                Enabled = true,
                RequireAuthenticatedUserByDefault = enabled
            });

        using var provider = services.BuildServiceProvider();

        var options = provider
            .GetRequiredService<IOptions<AuthorizationOptions>>()
            .Value;

        Assert.Equal(enabled, options.FallbackPolicy is not null);
    }

    [Fact]
    public async Task Registration_PreservesNativePolicies()
    {
        var services = new ServiceCollection();

        services.AddLogging();
        services.AddAuthorization(options =>
        {
            options.AddPolicy("NativePolicy", policy =>
                policy.RequireAuthenticatedUser());
        });

        services.AddEnterpriseAuthorization(
            new SecurityAuthorizationOptions
            {
                Enabled = true
            });

        using var provider = services.BuildServiceProvider();

        var policyProvider =            provider.GetRequiredService<IAuthorizationPolicyProvider>();
        var policy = await policyProvider.GetPolicyAsync("NativePolicy");

        Assert.NotNull(policy);
    }

    [Fact]
    public void DisabledAuthorization_DoesNotRequireConfiguration()
    {
        var services = new ServiceCollection();

        services.AddLogging();
        services.AddEnterpriseAuthorization(
            new SecurityAuthorizationOptions
            {
                Enabled = false,
                Policies = null!
            });

        using var provider = services.BuildServiceProvider();

        var options = provider
            .GetRequiredService<IOptions<AuthorizationOptions>>()
            .Value;

        Assert.Null(options.FallbackPolicy);
    }
}