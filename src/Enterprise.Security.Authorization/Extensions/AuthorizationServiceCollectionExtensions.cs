using Enterprise.Security.Authorization.Handlers;
using Enterprise.Security.Authorization.Requirements;
using Enterprise.Security.Core.Configuration;
using Enterprise.Security.Core.Configuration.AuthorizationConfig;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Enterprise.Security.Authorization.Extensions;

public static class AuthorizationServiceCollectionExtensions
{
    public static IServiceCollection AddEnterpriseAuthorization(this IServiceCollection services, SecurityAuthorizationOptions options)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);

        SecurityAuthorizationOptionsValidator.Validate(options);

        services.AddAuthorization();

        if (!options.Enabled)
            return services;

        var policies = options.Policies.ToDictionary(
            entry => entry.Key,
            entry => BuildPolicy(entry.Key),
            StringComparer.OrdinalIgnoreCase);

        var requireAuthenticationByDefault = options.RequireAuthenticatedUserByDefault;

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IAuthorizationHandler, PermissionHandler>());
        services.Configure<AuthorizationOptions>(authorization =>
        {
            foreach (var (name, policy) in policies)
            {
                if (authorization.GetPolicy(name) is not null)
                {
                    throw new InvalidOperationException(
                        $"Authorization policy '{name}' is already registered.");
                }

                authorization.AddPolicy(name, policy);
            }

            if (requireAuthenticationByDefault)
            {
                authorization.FallbackPolicy =
                    new AuthorizationPolicyBuilder()
                        .RequireAuthenticatedUser()
                        .Build();
            }
        });

        return services;

        AuthorizationPolicy BuildPolicy(string name)
        {
            var builder = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser();

            AddRules(builder, name);

            return builder.Build();
        }

        void AddRules(AuthorizationPolicyBuilder builder, string name)
        {
            var policy = options.Policies[name];
            if (policy.RequiredPermissions.Count > 0)
            {
                builder.AddRequirements(new PermissionRequirement(policy.RequiredPermissions));
            }

            foreach (var roleGroup in policy.RoleGroups)
            {
                builder.RequireRole(roleGroup);
            }

            foreach (var referencedPolicy in policy.RequiredPolicies)
            {
                AddRules(builder, referencedPolicy);
            }
        }
    }
}