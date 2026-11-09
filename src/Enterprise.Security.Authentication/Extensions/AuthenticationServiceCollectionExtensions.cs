using Enterprise.Security.Authentication.Claims;
using Enterprise.Security.Authentication.Handlers;
using Enterprise.Security.Core.Claims;
using Enterprise.Security.Core.Configuration.JwtConfig;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace Enterprise.Security.Authentication.Extensions;

public static class AuthenticationServiceCollectionExtensions
{
    public static AuthenticationBuilder AddEnterpriseJwtAuthentication(this IServiceCollection services, JwtAuthenticationOptions options)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);

        JwtAuthenticationOptionsValidator.Validate(options);

        var builder = services.AddAuthentication();

        if (!options.Enabled)
            return builder;

        var providerSchemes = options.Providers.Values
            .Select(provider => provider.Scheme)
            .ToArray();

        if (providerSchemes.Contains(MultiProviderJwtHandler.SchemeName, StringComparer.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"JWT provider schemes cannot use the reserved name '{MultiProviderJwtHandler.SchemeName}'.");
        }

        services.Configure<AuthenticationOptions>(authentication =>
        {
            authentication.DefaultAuthenticateScheme = MultiProviderJwtHandler.SchemeName;
            authentication.DefaultChallengeScheme = MultiProviderJwtHandler.SchemeName;
            authentication.DefaultForbidScheme = MultiProviderJwtHandler.SchemeName;
        });

        builder.AddScheme<MultiProviderJwtOptions, MultiProviderJwtHandler>(MultiProviderJwtHandler.SchemeName, multiProvider =>
            {
                multiProvider.ProviderSchemes = providerSchemes;
            });


        foreach (var provider in options.Providers.Values)
        {
            if (string.Equals(provider.PermissionClaimType, SecurityClaimTypes.Permission, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException($"JWT provider '{provider.Scheme}' uses a reserved permission claim type.");
            }

            builder.AddJwtBearer(provider.Scheme, jwt =>
            {
                jwt.Authority = provider.Authority;
                jwt.Audience = provider.Audience;
                jwt.RequireHttpsMetadata = true;

                // Preserve the provider's original claim names.
                jwt.MapInboundClaims = false;

                // Do not retain the bearer token in authentication properties.
                jwt.SaveToken = false;
                jwt.IncludeErrorDetails = false;

                // Refresh discovery keys when a signing key is unknown.
                jwt.RefreshOnIssuerKeyNotFound = true;

                jwt.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    RequireSignedTokens = true,
                    RequireExpirationTime = true,

                    ValidAudience = provider.Audience,
                    RoleClaimType = provider.RoleClaimType,
                    ClockSkew = TimeSpan.FromSeconds(30)
                };

                jwt.Events = new JwtBearerEvents
                {
                    OnTokenValidated = context =>
                    {
                        if (context.Principal is null)
                        {
                            context.Fail("The validated token has no principal.");
                            return Task.CompletedTask;
                        }

                        PermissionClaimsNormalizer.Normalize(
                            context.Principal,
                            provider.PermissionClaimType,
                            provider.ScopeClaimType,
                            provider.ScopeToPermissions);

                        return Task.CompletedTask;
                    }
                };
            });
        }

        return builder;
    }
}