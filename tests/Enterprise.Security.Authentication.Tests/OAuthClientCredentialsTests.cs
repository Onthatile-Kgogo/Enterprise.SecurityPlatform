using Enterprise.Security.Authentication.Extensions;
using Enterprise.Security.Core.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using System.Text;

namespace Enterprise.Security.Authentication.Tests
{
    public sealed class OAuthClientCredentialsTests
    {
        private const string TokenHttpClientName = "Enterprise.Security.OAuth.TokenEndpoint";
        private const string TokenEndpoint = "https://identity.example.test/oauth/token";

        [Fact]
        public void AddEnterpriseOAuthClientCredentials_LeavesProviderUnregisteredWhenDisabled()
        {
            var services = new ServiceCollection();
            var configuration = new ConfigurationBuilder().Build();

            services.AddEnterpriseOAuthClientCredentials(configuration);

            using var provider = services.BuildServiceProvider();
            Assert.Null(provider.GetService<IAccessTokenProvider>());
        }

        [Fact]
        public void AddEnterpriseOAuthClientCredentials_RejectsHttpEndpointDuringRegistration()
        {
            var services = new ServiceCollection();
            var configuration = CreateConfiguration("http://identity.example.test/oauth/token");

            var exception = Assert.Throws<InvalidOperationException>(() =>
            {
                services.AddEnterpriseOAuthClientCredentials(configuration);
            });

            Assert.Contains("HTTPS TokenEndpoint", exception.Message);
        }

        [Fact]
        public async Task GetAccessTokenAsync_ReusesOneRequestAcrossConcurrentCallers()
        {
            var calls = 0;
            var requestStarted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var releaseResponse = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            using var services = CreateServices(async (request, cancellationToken) =>
            {
                Interlocked.Increment(ref calls);
                requestStarted.TrySetResult(true);

                Assert.Equal(HttpMethod.Post, request.Method);
                Assert.Equal(new Uri(TokenEndpoint), request.RequestUri);

                var basicCredentials = Convert.ToBase64String(
                    Encoding.UTF8.GetBytes("service-id:test-secret"));
                Assert.Equal($"Basic {basicCredentials}", request.Headers.Authorization?.ToString());

                var body = await request.Content!.ReadAsStringAsync(cancellationToken);
                Assert.Equal("grant_type=client_credentials&scope=transactions.read", body);

                await releaseResponse.Task.WaitAsync(cancellationToken);
                return Success("first-token");
            });

            var provider = services.GetRequiredService<IAccessTokenProvider>();
            var first = provider.GetAccessTokenAsync("Transactions", timeout.Token).AsTask();
            await requestStarted.Task.WaitAsync(timeout.Token);

            var second = provider.GetAccessTokenAsync("TRANSACTIONS", timeout.Token).AsTask();
            releaseResponse.SetResult(true);

            var tokens = await Task.WhenAll(first, second);
            var cached = await provider.GetAccessTokenAsync("transactions", timeout.Token);

            Assert.Equal("first-token", tokens[0].Value);
            Assert.Same(tokens[0], tokens[1]);
            Assert.Same(tokens[0], cached);
            Assert.Equal(1, calls);
        }

        [Fact]
        public async Task GetAccessTokenAsync_AcquiresNewTokenAfterExpiry()
        {
            var calls = 0;
            var clock = new TestClock(DateTimeOffset.UtcNow);
            using var services = CreateServices((_, _) => Task.FromResult(Success($"token-{++calls}")), clock);

            var provider = services.GetRequiredService<IAccessTokenProvider>();
            var first = await provider.GetAccessTokenAsync("Transactions");

            clock.Advance(TimeSpan.FromSeconds(61));

            var second = await provider.GetAccessTokenAsync("Transactions");

            Assert.Equal("token-1", first.Value);
            Assert.Equal("token-2", second.Value);
            Assert.Equal(2, calls);
        }

        [Theory]
        [InlineData(HttpStatusCode.ServiceUnavailable, 3)]
        [InlineData(HttpStatusCode.Unauthorized, 1)]
        public async Task GetAccessTokenAsync_RetriesOnlyTransientHttpFailures(HttpStatusCode statusCode, int expectedAttempts)
        {
            var calls = 0;
            using var services = CreateServices((_, _) =>
            {
                Interlocked.Increment(ref calls);
                return Task.FromResult(new HttpResponseMessage(statusCode));
            });

            var provider = services.GetRequiredService<IAccessTokenProvider>();
            var exception = await Assert.ThrowsAsync<HttpRequestException>(async () =>
            {
                await provider.GetAccessTokenAsync("Transactions");
            });

            Assert.Equal<HttpStatusCode?>(statusCode, exception.StatusCode);
            Assert.Equal(expectedAttempts, calls);
        }

        private static IConfiguration CreateConfiguration(string tokenEndpoint = TokenEndpoint)
        {
            return new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["EnterpriseSecurity:OAuth:Enabled"] = "true",
                    ["EnterpriseSecurity:OAuth:Clients:Transactions:ClientId"] = "service-id",
                    ["EnterpriseSecurity:OAuth:Clients:Transactions:ClientSecret"] = "test-secret",
                    ["EnterpriseSecurity:OAuth:Clients:Transactions:TokenEndpoint"] = tokenEndpoint,
                    ["EnterpriseSecurity:OAuth:Clients:Transactions:Scopes:0"] = "transactions.read"
                })
                .Build();
        }

        private static ServiceProvider CreateServices(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send, TimeProvider? clock = null)
        {
            var services = new ServiceCollection();

            if (clock is not null)
            {
                services.AddSingleton<TimeProvider>(clock);
            }

            services.AddEnterpriseOAuthClientCredentials(CreateConfiguration());
            services.AddHttpClient(TokenHttpClientName)
                .ConfigurePrimaryHttpMessageHandler(() => new StubTokenHandler(send));

            return services.BuildServiceProvider();
        }

        private static HttpResponseMessage Success(string token)
        {
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    $$"""{"access_token":"{{token}}","token_type":"Bearer","expires_in":60}""",
                    Encoding.UTF8,
                    "application/json")
            };
        }

        private sealed class StubTokenHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                return send(request, cancellationToken);
            }
        }

        private sealed class TestClock(DateTimeOffset now) : TimeProvider
        {
            private DateTimeOffset _now = now;

            public override DateTimeOffset GetUtcNow() => _now;

            public void Advance(TimeSpan elapsed) => _now += elapsed;
        }
    }
}