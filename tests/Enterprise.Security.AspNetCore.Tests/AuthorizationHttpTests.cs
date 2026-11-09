using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using Enterprise.Security.AspNetCore.Attributes;
using Enterprise.Security.AspNetCore.Extensions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Enterprise.Security.AspNetCore.Tests;

public sealed class AuthorizationHttpTests : IDisposable
{
    private const string Issuer = "https://identity.example.com";
    private const string Audience = "transactions-api";
    private const string Scheme = "TestJwt";

    private readonly RSA _rsa = RSA.Create(2048);
    private readonly IHost _host;
    private readonly HttpClient _client;

    public AuthorizationHttpTests()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["EnterpriseSecurity:Authentication:Enabled"] = "true",
                ["EnterpriseSecurity:Authentication:Providers:primary:Scheme"] = Scheme,
                ["EnterpriseSecurity:Authentication:Providers:primary:Authority"] = Issuer,
                ["EnterpriseSecurity:Authentication:Providers:primary:Audience"] = Audience,
                ["EnterpriseSecurity:Authentication:Providers:primary:RoleClaimType"] = "roles",
                ["EnterpriseSecurity:Authentication:Providers:primary:PermissionClaimType"] = "permissions",
                ["EnterpriseSecurity:Authentication:Providers:primary:ScopeToPermissions:transactions.view:0"] = "transactions.read",
                ["EnterpriseSecurity:Authorization:Enabled"] = "true",
                ["EnterpriseSecurity:Authorization:RequireAuthenticatedUserByDefault"] = "true",
                ["EnterpriseSecurity:Authorization:Policies:CanRead:RequiredPermissions:0"] = "transactions.read",
                ["EnterpriseSecurity:Authorization:Policies:CanView:RequiredPolicies:0"] = "CanRead"
            })
            .Build();

        _host = new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services =>
                {
                    services.AddLogging();
                    services.AddControllers()                        .AddApplicationPart(typeof(AuthorizationProbeController).Assembly);
                    services.AddEnterpriseSecurity(configuration);
                    services.Configure<JwtBearerOptions>(Scheme, jwt =>
                    {
                        var metadata = new OpenIdConnectConfiguration
                        {
                            Issuer = Issuer
                        };

                        metadata.SigningKeys.Add(
                            new RsaSecurityKey(_rsa.ExportParameters(false))
                            {
                                KeyId = "test-key"
                            });

                        jwt.ConfigurationManager =
                            new StaticConfigurationManager<OpenIdConnectConfiguration>(metadata);
                    });
                })
                .Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseAuthorization();

                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapControllers();
                        endpoints.MapGet("/unannotated", context =>                            context.Response.WriteAsync("OK"));
                    });
                }))
            .Start();

        _client = _host.GetTestClient();
    }

    [Theory]
    [InlineData("/authorization-probe/read", false, null, false, 401)]
    [InlineData("/authorization-probe/read", true, "Viewer", true, 403)]
    [InlineData("/authorization-probe/read", true, "Operator", false, 403)]
    [InlineData("/authorization-probe/read", true, "Operator", true, 200)]
    [InlineData("/authorization-probe/read", true, "Admin", true, 200)]
    [InlineData("/authorization-probe/named", true, "Operator", false, 403)]
    [InlineData("/authorization-probe/named", true, "Operator", true, 200)]
    [InlineData("/authorization-probe/anonymous", false, null, false, 200)]
    [InlineData("/unannotated", false, null, false, 401)]
    [InlineData("/unannotated", true, null, false, 200)]
    public async Task Endpoint_EnforcesAuthorization(string path, bool authenticated, string? role, bool hasPermission, int expectedStatus)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);

        if (authenticated)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", CreateToken(role, hasPermission));
        }

        using var response = await _client.SendAsync(request);

        Assert.Equal((HttpStatusCode)expectedStatus, response.StatusCode);

        if (expectedStatus == 401)
        {
            Assert.Contains(response.Headers.WwwAuthenticate, header => header.Scheme == "Bearer");
        }
    }

    [Fact]
    public async Task MappedScope_GrantsRequiredPermission()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/authorization-probe/read");

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", CreateToken("Operator", false, scope: "transactions.view"));

        using var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task IncomingInternalPermissionClaim_DoesNotGrantAccess()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/authorization-probe/read");

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", CreateToken("Operator", false, injectInternalPermission: true));

        using var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task InvalidToken_Returns401()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/authorization-probe/read");

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "not-a-jwt");

        using var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    private string CreateToken(string? role, bool hasPermission, string? scope = null, bool injectInternalPermission = false)
    {
        var claims = new List<Claim>
        {
            new("sub", "test-client")
        };

        if (role is not null)
            claims.Add(new Claim("roles", role));

        if (hasPermission)
            claims.Add(new Claim("permissions", "transactions.read"));

        if (scope is not null)
            claims.Add(new Claim("scope", scope));

        if (injectInternalPermission)
            claims.Add(new Claim("enterprise_security_permission", "transactions.read"));

        var now = DateTime.UtcNow;

        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            Audience = Audience,
            Subject = new ClaimsIdentity(claims),
            IssuedAt = now,
            NotBefore = now.AddMinutes(-1),
            Expires = now.AddMinutes(10),
            SigningCredentials = new SigningCredentials(
                new RsaSecurityKey(_rsa)
                {
                    KeyId = "test-key"
                },
                SecurityAlgorithms.RsaSha256)
        });
    }

    public void Dispose()
    {
        _client.Dispose();
        _host.Dispose();
        _rsa.Dispose();
    }
}

[ApiController]
[Route("authorization-probe")]
[AuthorizeClient(Roles = "Admin,Operator")]
public sealed class AuthorizationProbeController : ControllerBase
{
    [HttpGet("read")]
    [AuthorizeClient(Permissions = "transactions.read")]
    public IActionResult Read() => Ok();

    [HttpGet("named")]
    [AuthorizeClient(Policy = "CanView")]
    public IActionResult Named() => Ok();

    [HttpGet("anonymous")]
    [AllowAnonymous]
    public IActionResult Anonymous() => Ok();
}