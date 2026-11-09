using System.Net;
using Enterprise.Security.Core.Abstractions;
using Enterprise.Security.Core.Configuration.OAuthConfig;
using Enterprise.Security.Core.Models;

namespace Enterprise.Security.Authentication.OAuth
{
    internal sealed class ClientCredentialsAccessTokenProvider : IAccessTokenProvider
    {
        private const int MaxAttempts = 3;

        private readonly Dictionary<string, ClientState> _clients = new(StringComparer.OrdinalIgnoreCase);

        private readonly IClientCredentialProvider _credentialProvider;
        private readonly ITokenCache _cache;
        private readonly ClientCredentialsTokenClient _tokenClient;
        private readonly TimeProvider _timeProvider;

        public ClientCredentialsAccessTokenProvider(OAuthOptions options, IClientCredentialProvider credentialProvider, ITokenCache cache, ClientCredentialsTokenClient tokenClient, TimeProvider timeProvider)
        {
            _credentialProvider = credentialProvider;
            _cache = cache;
            _tokenClient = tokenClient;
            _timeProvider = timeProvider;

            foreach (var (clientName, client) in options.Clients)
            {
                _clients.Add(clientName, new ClientState(clientName, client));
            }
        }

        public async ValueTask<AccessToken> GetAccessTokenAsync(string clientName, CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(clientName);
            cancellationToken.ThrowIfCancellationRequested();

            if (!_clients.TryGetValue(clientName, out var client))
            {
                throw new KeyNotFoundException($"OAuth client '{clientName}' is not configured.");
            }

            var cachedToken = await GetValidCachedTokenAsync(client.CacheKey, cancellationToken);
            if (cachedToken is not null)
                return cachedToken;


            await client.RefreshLock.WaitAsync(cancellationToken);
            try
            {
                // Another caller may have fetched a token while this caller was waiting.
                cachedToken = await GetValidCachedTokenAsync(client.CacheKey, cancellationToken);
                if (cachedToken is not null)
                    return cachedToken;

                var credentials = await _credentialProvider.GetCredentialsAsync(client.Name, cancellationToken);
                var token = await RequestWithRetryAsync(client, credentials, cancellationToken);
                await _cache.SetAsync(client.CacheKey, token, cancellationToken);

                return token;
            }
            finally
            {
                client.RefreshLock.Release();
            }
        }

        private async ValueTask<AccessToken?> GetValidCachedTokenAsync(string cacheKey, CancellationToken cancellationToken)
        {
            var token = await _cache.GetAsync(cacheKey, cancellationToken);
            return token is not null && token.ExpiresAtUtc > _timeProvider.GetUtcNow()
                ? token
                : null;
        }

        private async Task<AccessToken> RequestWithRetryAsync(ClientState client, ClientCredentials credentials, CancellationToken cancellationToken)
        {
            for (var attempt = 1; ; attempt++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var requestStartedAt = _timeProvider.GetUtcNow();

                try
                {
                    var response = await _tokenClient.RequestTokenAsync(client.Endpoint, credentials, client.Scopes, cancellationToken);
                    var expiresAt = requestStartedAt.AddSeconds(response.ExpiresInSeconds);
                    if (expiresAt <= _timeProvider.GetUtcNow())
                    {
                        throw new InvalidOperationException(
                            "The access token expired before the request completed.");
                    }

                    // The token endpoint client has already checked the value.
                    return new AccessToken(response.AccessToken!, expiresAt);
                }
                catch (Exception exception) when (attempt < MaxAttempts && !cancellationToken.IsCancellationRequested && IsTransient(exception))
                {
                    var delayMilliseconds = 200 * (1 << (attempt - 1)) + Random.Shared.Next(0, 101);

                    await Task.Delay(TimeSpan.FromMilliseconds(delayMilliseconds), _timeProvider, cancellationToken);
                }
            }
        }

        private static bool IsTransient(Exception exception)
        {
            return exception switch
            {
                HttpRequestException { StatusCode: { } status } => status is
                    HttpStatusCode.RequestTimeout or
                    HttpStatusCode.TooManyRequests or
                    HttpStatusCode.InternalServerError or
                    HttpStatusCode.BadGateway or
                    HttpStatusCode.ServiceUnavailable or
                    HttpStatusCode.GatewayTimeout,

                HttpRequestException requestException => requestException.HttpRequestError is
                    HttpRequestError.NameResolutionError or
                    HttpRequestError.ConnectionError or
                    HttpRequestError.ResponseEnded,

                OperationCanceledException { InnerException: TimeoutException } => true,

                _ => false
            };
        }

        private sealed class ClientState
        {
            public ClientState(string name, OAuthClientOptions options)
            {
                Name = name;
                CacheKey = $"enterprise-security:oauth:{name}";
                Endpoint = new Uri(options.TokenEndpoint, UriKind.Absolute);
                Scopes = options.Scopes;
            }

            public string Name { get; }
            public string CacheKey { get; }
            public Uri Endpoint { get; }
            public string[] Scopes { get; }
            public SemaphoreSlim RefreshLock { get; } = new(1, 1);
        }
    }
}