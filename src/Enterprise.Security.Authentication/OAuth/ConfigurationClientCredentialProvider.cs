using Enterprise.Security.Core.Abstractions;
using Enterprise.Security.Core.Configuration.OAuthConfig;
using Enterprise.Security.Core.Models;

namespace Enterprise.Security.Authentication.OAuth
{
    internal sealed class ConfigurationClientCredentialProvider : IClientCredentialProvider
    {
        private readonly OAuthOptions _options;

        public ConfigurationClientCredentialProvider(OAuthOptions options)
        {
            ArgumentNullException.ThrowIfNull(options);
            _options = options;
        }

        public ValueTask<ClientCredentials> GetCredentialsAsync(string clientName, CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(clientName);
            cancellationToken.ThrowIfCancellationRequested();

            if (!_options.Enabled)
            {
                throw new InvalidOperationException("OAuth client credentials are disabled.");
            }

            if (!_options.Clients.TryGetValue(clientName, out var client))
            {
                throw new KeyNotFoundException($"OAuth client '{clientName}' is not configured.");
            }

            return ValueTask.FromResult(new ClientCredentials(client.ClientId, client.ClientSecret));
        }
    }
}