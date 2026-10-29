using System;
using System.Collections.Generic;
using System.Text;

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
