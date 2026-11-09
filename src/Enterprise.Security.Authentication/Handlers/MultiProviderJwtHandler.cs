using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Enterprise.Security.Authentication.Handlers;

public sealed class MultiProviderJwtHandler : AuthenticationHandler<MultiProviderJwtOptions>
{
    public const string SchemeName = "EnterpriseSecurity.Jwt";

    public MultiProviderJwtHandler(IOptionsMonitor<MultiProviderJwtOptions> options, ILoggerFactory logger, UrlEncoder encoder) : base(options, logger, encoder)
    {
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var failed = false;

        foreach (var providerScheme in Options.ProviderSchemes)
        {
            Context.RequestAborted.ThrowIfCancellationRequested();

            var result = await Context.AuthenticateAsync(providerScheme);

            if (result.Succeeded)
                return result;


            if (result.Failure is not null)
                failed = true;

        }

        return failed
            ? AuthenticateResult.Fail("The bearer token was rejected by the configured providers.")
            : AuthenticateResult.NoResult();
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.Headers["WWW-Authenticate"] = "Bearer";

        return Task.CompletedTask;
    }

    protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status403Forbidden;
        return Task.CompletedTask;
    }
}