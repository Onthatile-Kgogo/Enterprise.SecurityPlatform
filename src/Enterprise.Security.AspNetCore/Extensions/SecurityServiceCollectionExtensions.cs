using Enterprise.Security.Authentication.Extensions;
using Enterprise.Security.Authorization.Extensions;
using Enterprise.Security.Core.Configuration.AuthorizationConfig;
using Enterprise.Security.Core.Configuration.JwtConfig;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Enterprise.Security.AspNetCore.Extensions;

public static class SecurityServiceCollectionExtensions
{
    public static IServiceCollection AddEnterpriseSecurity(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        var authentication = configuration
            .GetSection(JwtAuthenticationOptions.SectionName)
            .Get<JwtAuthenticationOptions>() ?? new JwtAuthenticationOptions();

        var authorization = configuration
            .GetSection(SecurityAuthorizationOptions.SectionName)
            .Get<SecurityAuthorizationOptions>() ?? new SecurityAuthorizationOptions();

        services.AddEnterpriseJwtAuthentication(authentication);
        services.AddEnterpriseAuthorization(authorization);
        services.AddEnterpriseOAuthClientCredentials(configuration);

        return services;
    }
}