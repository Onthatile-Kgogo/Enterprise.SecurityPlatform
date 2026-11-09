using Enterprise.Security.Core.Claims;

namespace Enterprise.Security.Core.Configuration.JwtConfig
{
    public static class JwtAuthenticationOptionsValidator
    {
        public static void Validate(JwtAuthenticationOptions options)
        {
            ArgumentNullException.ThrowIfNull(options);

            if (!options.Enabled)
                return;

            if (options.Providers is null || options.Providers.Count == 0)
            {
                throw new InvalidOperationException("At least one JWT provider must be configured when authentication is enabled.");
            }

            var schemes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var (providerName, provider) in options.Providers)
            {
                if (string.Equals(provider.PermissionClaimType, SecurityClaimTypes.Permission, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException($"JWT provider '{providerName}' uses a reserved PermissionClaimType.");
                }

                if (string.IsNullOrWhiteSpace(provider.ScopeClaimType))
                {
                    throw new InvalidOperationException($"JWT provider '{providerName}' requires a ScopeClaimType.");
                }

                if (string.Equals(provider.ScopeClaimType, SecurityClaimTypes.Permission, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException($"JWT provider '{providerName}' uses a reserved ScopeClaimType.");
                }

                if (provider.ScopeToPermissions is null)
                {
                    throw new InvalidOperationException($"JWT provider '{providerName}' scope mappings cannot be null.");
                }

                foreach (var (scope, permissions) in provider.ScopeToPermissions)
                {
                    if (string.IsNullOrWhiteSpace(scope) || scope.Any(char.IsWhiteSpace))
                    {
                        throw new InvalidOperationException($"JWT provider '{providerName}' contains an invalid scope mapping key.");
                    }

                    if (permissions is null || permissions.Count == 0 || permissions.Any(string.IsNullOrWhiteSpace))
                    {
                        throw new InvalidOperationException($"JWT provider '{providerName}' scope '{scope}' requires non-empty permissions.");
                    }
                }
                if (string.IsNullOrWhiteSpace(providerName))
                {
                    throw new InvalidOperationException("JWT provider names cannot be empty.");
                }

                if (provider is null)
                {
                    throw new InvalidOperationException($"JWT provider '{providerName}' configuration is missing.");
                }

                if (string.IsNullOrWhiteSpace(provider.Scheme))
                {
                    throw new InvalidOperationException($"JWT provider '{providerName}' requires a Scheme.");
                }

                if (!schemes.Add(provider.Scheme))
                {
                    throw new InvalidOperationException($"Duplicate JWT authentication scheme '{provider.Scheme}'.");
                }

                if (!Uri.TryCreate(provider.Authority, UriKind.Absolute, out var authority) ||
                    authority.Scheme != Uri.UriSchemeHttps ||
                    string.IsNullOrWhiteSpace(authority.Host) ||
                    !string.IsNullOrEmpty(authority.UserInfo))
                {
                    throw new InvalidOperationException($"JWT provider '{providerName}' requires a valid HTTPS Authority.");
                }

                if (string.IsNullOrWhiteSpace(provider.Audience))
                {
                    throw new InvalidOperationException($"JWT provider '{providerName}' requires an Audience.");
                }

                if (!provider.RequireHttpsMetadata)
                {
                    throw new InvalidOperationException($"JWT provider '{providerName}' must require HTTPS metadata.");
                }

                if (string.IsNullOrWhiteSpace(provider.RoleClaimType))
                {
                    throw new InvalidOperationException($"JWT provider '{providerName}' requires a RoleClaimType.");
                }

                if (string.IsNullOrWhiteSpace(provider.PermissionClaimType))
                {
                    throw new InvalidOperationException($"JWT provider '{providerName}' requires a PermissionClaimType.");
                }
            }
        }
    }
}
