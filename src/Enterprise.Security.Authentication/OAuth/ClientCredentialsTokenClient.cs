using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json.Serialization;
using Enterprise.Security.Core.Models;

namespace Enterprise.Security.Authentication.OAuth
{
    internal sealed class ClientCredentialsTokenClient
    {
        internal const string HttpClientName = "Enterprise.Security.OAuth.TokenEndpoint";
        private readonly IHttpClientFactory _httpClientFactory;

        public ClientCredentialsTokenClient(IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory;
        }

        public async Task<TokenEndpointResponse> RequestTokenAsync(Uri tokenEndpoint, ClientCredentials credentials, string[] scopes, CancellationToken cancellationToken = default)
        {
            if (!tokenEndpoint.IsAbsoluteUri || tokenEndpoint.Scheme != Uri.UriSchemeHttps || string.IsNullOrEmpty(tokenEndpoint.Host) || !string.IsNullOrEmpty(tokenEndpoint.UserInfo))
            {
                throw new ArgumentException("The token endpoint must be an HTTPS URI without embedded credentials.", nameof(tokenEndpoint));
            }

            var fields = new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials"
            };

            if (scopes.Length > 0)
            {
                fields["scope"] = string.Join(" ", scopes);
            }

            var clientId = WebUtility.UrlEncode(credentials.ClientId);
            var clientSecret = WebUtility.UrlEncode(credentials.ClientSecret);
            var basicCredentials = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{clientId}:{clientSecret}"));

            using var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
            {
                Content = new FormUrlEncodedContent(fields)
            };

            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", basicCredentials);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            using var httpClient = _httpClientFactory.CreateClient(HttpClientName);
            using var response = await httpClient.SendAsync(request, cancellationToken);

            response.EnsureSuccessStatusCode();

            var token = await response.Content.ReadFromJsonAsync<TokenEndpointResponse>(cancellationToken: cancellationToken);

            if (token is null || string.IsNullOrWhiteSpace(token.AccessToken) || !string.Equals(token.TokenType, "Bearer", StringComparison.OrdinalIgnoreCase) || token.ExpiresInSeconds <= 0)
            {
                throw new InvalidOperationException("The token endpoint must return a Bearer access token with a positive lifetime.");
            }

            return token;
        }

        internal sealed class TokenEndpointResponse
        {
            [JsonPropertyName("access_token")]
            public string? AccessToken { get; init; }

            [JsonPropertyName("token_type")]
            public string? TokenType { get; init; }

            [JsonPropertyName("expires_in")]
            public int ExpiresInSeconds { get; init; }
        }
    }
}