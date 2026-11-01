using Enterprise.Security.Authentication.Extensions;
using Enterprise.Security.Authentication.Handlers;
using Enterprise.Security.Core.Configuration.JwtConfig;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Enterprise.Security.Authentication.Tests;

public sealed class JwtAuthenticationRegistrationTests
{
    [Fact]
    public async Task Enabled_RegistersProvidersAndDefaultScheme()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddEnterpriseJwtAuthentication(CreateOptions());

        using var provider = services.BuildServiceProvider();

        var schemes = provider.GetRequiredService<IAuthenticationSchemeProvider>();

        Assert.NotNull(await schemes.GetSchemeAsync("ProviderA"));
        Assert.NotNull(await schemes.GetSchemeAsync("ProviderB"));
        Assert.Equal(MultiProviderJwtHandler.SchemeName, (await schemes.GetDefaultAuthenticateSchemeAsync())?.Name);
        Assert.Equal(MultiProviderJwtHandler.SchemeName, (await schemes.GetDefaultChallengeSchemeAsync())?.Name);
        Assert.Equal(MultiProviderJwtHandler.SchemeName, (await schemes.GetDefaultForbidSchemeAsync())?.Name);
    }

    [Fact]
    public void Providers_KeepIndependentValidationSettings()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddEnterpriseJwtAuthentication(CreateOptions());

        using var provider = services.BuildServiceProvider();

        var monitor = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>();

        var first = monitor.Get("ProviderA");
        var second = monitor.Get("ProviderB");

        Assert.Equal("https://identity-a.example.com", first.Authority);
        Assert.Equal("api-a", first.TokenValidationParameters.ValidAudience);
        Assert.Equal("role", first.TokenValidationParameters.RoleClaimType);

        Assert.Equal("https://identity-b.example.com", second.Authority);
        Assert.Equal("api-b", second.TokenValidationParameters.ValidAudience);
        Assert.Equal("roles", second.TokenValidationParameters.RoleClaimType);

        foreach (var jwt in new[] { first, second })
        {
            var validation = jwt.TokenValidationParameters;

            Assert.True(jwt.RequireHttpsMetadata);
            Assert.True(jwt.RefreshOnIssuerKeyNotFound);
            Assert.False(jwt.MapInboundClaims);
            Assert.False(jwt.SaveToken);
            Assert.False(jwt.IncludeErrorDetails);

            Assert.True(validation.ValidateIssuer);
            Assert.True(validation.ValidateAudience);
            Assert.True(validation.ValidateLifetime);
            Assert.True(validation.ValidateIssuerSigningKey);
            Assert.True(validation.RequireSignedTokens);
            Assert.True(validation.RequireExpirationTime);
        }
    }

    [Fact]
    public async Task Disabled_RegistersNoEnterpriseSchemes()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddEnterpriseJwtAuthentication(new JwtAuthenticationOptions { Enabled = false });

        using var provider = services.BuildServiceProvider();

        var schemes = provider.GetRequiredService<IAuthenticationSchemeProvider>();

        Assert.Empty(await schemes.GetAllSchemesAsync());
        Assert.Null(await schemes.GetDefaultAuthenticateSchemeAsync());
    }

    [Fact]
    public void ReservedSchemeName_IsRejectedDuringRegistration()
    {
        var options = CreateOptions();
        options.Providers["First"].Scheme = MultiProviderJwtHandler.SchemeName;

        var services = new ServiceCollection();

        Assert.Throws<InvalidOperationException>(() =>
        {
            services.AddEnterpriseJwtAuthentication(options);
        });
    }

    private static JwtAuthenticationOptions CreateOptions()
    {
        return new JwtAuthenticationOptions
        {
            Enabled = true,
            Providers = new Dictionary<string, JwtProviderOptions>
            {
                ["First"] = new()
                {
                    Scheme = "ProviderA",
                    Authority = "https://identity-a.example.com",
                    Audience = "api-a",
                    RoleClaimType = "role"
                },
                ["Second"] = new()
                {
                    Scheme = "ProviderB",
                    Authority = "https://identity-b.example.com",
                    Audience = "api-b",
                    RoleClaimType = "roles"
                }
            }
        };
    }
}