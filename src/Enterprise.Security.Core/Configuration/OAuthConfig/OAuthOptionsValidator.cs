namespace Enterprise.Security.Core.Configuration.OAuthConfig
{
    public static class OAuthOptionsValidator
    {
        public static void Validate(OAuthOptions options)
        {
            ArgumentNullException.ThrowIfNull(options);

            // Disabled features do not require configuration.
            if (!options.Enabled)
                return;

            if (options.Clients is null || options.Clients.Count == 0)
            {
                throw new InvalidOperationException("At least one OAuth client must be configured when OAuth is enabled.");
            }

            foreach (var (clientName, client) in options.Clients)
            {
                if (string.IsNullOrWhiteSpace(clientName))
                {
                    throw new InvalidOperationException("OAuth client names cannot be empty.");
                }

                if (client is null)
                {
                    throw new InvalidOperationException($"OAuth client '{clientName}' configuration is missing.");
                }

                if (string.IsNullOrWhiteSpace(client.ClientId))
                {
                    throw new InvalidOperationException($"OAuth client '{clientName}' requires a ClientId.");
                }

                if (string.IsNullOrWhiteSpace(client.ClientSecret))
                {
                    throw new InvalidOperationException($"OAuth client '{clientName}' requires a ClientSecret.");
                }

                if (!Uri.TryCreate(client.TokenEndpoint, UriKind.Absolute, out var endpoint) ||
                    endpoint.Scheme != Uri.UriSchemeHttps ||
                    string.IsNullOrWhiteSpace(endpoint.Host) ||
                    !string.IsNullOrEmpty(endpoint.UserInfo))
                {
                    throw new InvalidOperationException($"OAuth client '{clientName}' requires a valid HTTPS TokenEndpoint.");
                }
            }
        }
    }
}
