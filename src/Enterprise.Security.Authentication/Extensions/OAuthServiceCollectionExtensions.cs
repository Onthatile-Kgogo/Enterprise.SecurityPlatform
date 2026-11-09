using Enterprise.Security.Authentication.OAuth;
using Enterprise.Security.Core.Abstractions;
using Enterprise.Security.Core.Configuration.OAuthConfig;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Enterprise.Security.Authentication.Extensions
{
    public static class OAuthServiceCollectionExtensions
    {
        public static IServiceCollection AddEnterpriseOAuthClientCredentials(this IServiceCollection services, IConfiguration configuration)
        {
            ArgumentNullException.ThrowIfNull(services);
            ArgumentNullException.ThrowIfNull(configuration);

            var options = configuration
                .GetSection(OAuthOptions.SectionName)
                .Get<OAuthOptions>() ?? new OAuthOptions();

            OAuthOptionsValidator.Validate(options);

            if (!options.Enabled)
            {
                return services;
            }

            services.AddMemoryCache();
            services.AddHttpClient(ClientCredentialsTokenClient.HttpClientName, client =>
            {
                client.Timeout = TimeSpan.FromSeconds(10);
            })
            .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
            {
                AllowAutoRedirect = false,
                UseCookies = false
            });

            services.TryAddSingleton<TimeProvider>(TimeProvider.System);
            services.TryAddSingleton<IClientCredentialProvider>(
                _ => new ConfigurationClientCredentialProvider(options));
            services.TryAddSingleton<ITokenCache, MemoryTokenCache>();
            services.TryAddSingleton<ClientCredentialsTokenClient>();

            services.TryAddSingleton<IAccessTokenProvider>(provider =>
                new ClientCredentialsAccessTokenProvider(
                    options,
                    provider.GetRequiredService<IClientCredentialProvider>(),
                    provider.GetRequiredService<ITokenCache>(),
                    provider.GetRequiredService<ClientCredentialsTokenClient>(),
                    provider.GetRequiredService<TimeProvider>()));

            return services;
        }
    }
}