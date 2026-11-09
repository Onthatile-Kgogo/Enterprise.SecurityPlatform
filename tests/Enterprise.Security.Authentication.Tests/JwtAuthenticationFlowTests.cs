using Enterprise.Security.Authentication.Extensions;
using Enterprise.Security.Core.Configuration.JwtConfig;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;

namespace Enterprise.Security.Authentication.Tests;

public sealed class JwtAuthenticationFlowTests : IDisposable
{
    private readonly RSA _firstRsa = RSA.Create(2048);
    private readonly RSA _secondRsa = RSA.Create(2048);

    [Theory]
    [InlineData("ProviderA")]
    [InlineData("ProviderB")]
    public async Task ValidToken_AuthenticatesThroughDefaultScheme(
        string scheme)
    {
        using var services = CreateServices();
        using var scope = services.CreateScope();

        var context = CreateContext(scope.ServiceProvider, CreateToken(scheme));

        var result = await context.AuthenticateAsync();

        Assert.True(result.Succeeded);
        Assert.Equal(scheme, result.Ticket?.AuthenticationScheme);
        Assert.Equal("test-client", result.Principal?.FindFirst("sub")?.Value);
        Assert.True(result.Principal?.IsInRole("Admin") == true);
    }

    [Theory]
    [InlineData("issuer")]
    [InlineData("audience")]
    [InlineData("signature")]
    [InlineData("expired")]
    [InlineData("future")]
    [InlineData("unsigned")]
    [InlineData("missing-expiry")]
    [InlineData("malformed")]
    public async Task InvalidToken_IsRejected(string failure)
    {
        using var services = CreateServices();
        using var scope = services.CreateScope();

        var token = failure == "malformed"
            ? "not-a-jwt"
            : CreateToken("ProviderA", failure);

        var context = CreateContext(scope.ServiceProvider, token);

        var result = await context.AuthenticateAsync();

        Assert.False(result.Succeeded);
        Assert.NotNull(result.Failure);
        Assert.Null(result.Principal);

        await context.ChallengeAsync();

        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        Assert.Equal("Bearer", context.Response.Headers["WWW-Authenticate"].ToString());
    }

    [Fact]
    public async Task ProviderAToken_CannotAuthenticateAsProviderB()
    {
        using var services = CreateServices();
        using var scope = services.CreateScope();

        var context = CreateContext(scope.ServiceProvider, CreateToken("ProviderA"));
        var result = await context.AuthenticateAsync("ProviderB");

        Assert.False(result.Succeeded);
        Assert.Null(result.Principal);
    }

    [Fact]
    public async Task MissingToken_ReturnsNoResultAndChallengesWith401()
    {
        using var services = CreateServices();
        using var scope = services.CreateScope();

        var context = CreateContext(scope.ServiceProvider);

        var result = await context.AuthenticateAsync();

        Assert.True(result.None);

        await context.ChallengeAsync();

        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        Assert.Equal("Bearer", context.Response.Headers["WWW-Authenticate"].ToString());
    }

    [Fact]
    public async Task ForbiddenAuthenticatedRequest_Returns403()
    {
        using var services = CreateServices();
        using var scope = services.CreateScope();

        var context = CreateContext(scope.ServiceProvider, CreateToken("ProviderA"));
        var result = await context.AuthenticateAsync();

        Assert.True(result.Succeeded);

        context.User = result.Principal!;

        await context.ForbidAsync();
        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
    }

    private ServiceProvider CreateServices()
    {
        var services = new ServiceCollection();
        services.AddLogging();

        services.AddEnterpriseJwtAuthentication(
            new JwtAuthenticationOptions
            {
                Enabled = true,
                Providers = new Dictionary<string, JwtProviderOptions>
                {
                    ["First"] = new()
                    {
                        Scheme = "ProviderA",
                        Authority = Issuer("ProviderA"),
                        Audience = "api-a",
                        RoleClaimType = "role"
                    },
                    ["Second"] = new()
                    {
                        Scheme = "ProviderB",
                        Authority = Issuer("ProviderB"),
                        Audience = "api-b",
                        RoleClaimType = "roles"
                    }
                }
            });

        ConfigureMetadata(services, "ProviderA", _firstRsa);
        ConfigureMetadata(services, "ProviderB", _secondRsa);

        return services.BuildServiceProvider();
    }

    private static void ConfigureMetadata(IServiceCollection services, string scheme, RSA rsa)
    {
        // Publish only the public key in the test provider's metadata.
        var publicKey = new RsaSecurityKey(rsa.ExportParameters(false))
        {
            KeyId = scheme
        };

        services.Configure<JwtBearerOptions>(scheme, jwt =>
        {
            var metadata = new OpenIdConnectConfiguration
            {
                Issuer = Issuer(scheme)
            };

            metadata.SigningKeys.Add(publicKey);

            jwt.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(metadata);
        });
    }

    private string CreateToken(string scheme, string? failure = null)
    {
        var now = DateTime.UtcNow;
        var rsa = scheme == "ProviderA" ? _firstRsa : _secondRsa;

        if (failure == "signature")
        {
            rsa = _secondRsa;
        }

        var signingKey = new RsaSecurityKey(rsa)
        {
            KeyId = scheme
        };

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = failure == "issuer"
                ? "https://untrusted.example.com"
                : Issuer(scheme),

            Audience = failure == "audience"
                ? "wrong-api"
                : scheme == "ProviderA" ? "api-a" : "api-b",

            Subject = new ClaimsIdentity(
            [
                new Claim("sub", "test-client"),
                new Claim(
                    scheme == "ProviderA" ? "role" : "roles",
                    "Admin")
            ]),

            IssuedAt = now.AddHours(-2),

            NotBefore = failure == "future"
                ? now.AddMinutes(10)
                : now.AddHours(-2),

            Expires = failure switch
            {
                "expired" => now.AddMinutes(-10),
                "missing-expiry" => null,
                _ => now.AddHours(1)
            },

            SigningCredentials = failure == "unsigned"
                ? null
                : new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256)
        };

        return new JsonWebTokenHandler
        {
            SetDefaultTimesOnTokenCreation = false
        }.CreateToken(descriptor);
    }

    private static DefaultHttpContext CreateContext(
        IServiceProvider services,
        string? token = null)
    {
        var context = new DefaultHttpContext
        {
            RequestServices = services
        };

        if (token is not null)
        {
            context.Request.Headers["Authorization"] = $"Bearer {token}";
        }

        return context;
    }

    private static string Issuer(string scheme) =>
        scheme == "ProviderA"
            ? "https://identity-a.example.com"
            : "https://identity-b.example.com";

    public void Dispose()
    {
        _firstRsa.Dispose();
        _secondRsa.Dispose();
    }
}