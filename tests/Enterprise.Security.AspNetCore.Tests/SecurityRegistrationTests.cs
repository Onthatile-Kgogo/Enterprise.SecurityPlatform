using Enterprise.Security.AspNetCore.Extensions;
using Enterprise.Security.Core.Abstractions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Enterprise.Security.AspNetCore.Tests;

public sealed class SecurityRegistrationTests
{
    [Theory]
    [InlineData("Authentication", "At least one JWT provider")]
    [InlineData("OAuth", "At least one OAuth client")]
    public void EnabledFeatureWithoutRequiredSettings_FailsDuringRegistration(        string feature,        string expectedMessage)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"EnterpriseSecurity:{feature}:Enabled"] = "true"
            })
            .Build();

        var services = new ServiceCollection();
        var exception = Assert.Throws<InvalidOperationException>(() =>            services.AddEnterpriseSecurity(configuration));

        Assert.Contains(expectedMessage, exception.Message);
    }

    [Fact]
    public async Task MissingConfiguration_LeavesJwtAndOAuthDisabled()
    {
        var configuration = new ConfigurationBuilder().Build();
        var services = new ServiceCollection();

        services.AddEnterpriseSecurity(configuration);

        using var provider = services.BuildServiceProvider();

        var schemes = provider.GetRequiredService<IAuthenticationSchemeProvider>();

        Assert.Empty(await schemes.GetAllSchemesAsync());
        Assert.Null(provider.GetService<IAccessTokenProvider>());
    }
}