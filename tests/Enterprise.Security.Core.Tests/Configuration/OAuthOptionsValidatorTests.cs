using Enterprise.Security.Core.Configuration.OAuthConfig;
using Xunit;

namespace Enterprise.Security.Core.Tests.Configuration;

public sealed class OAuthOptionsValidatorTests
{
    [Fact]
    public void Validate_WhenOAuthDisabled_ShouldSucceed()
    {
        var options = new OAuthOptions { Enabled = false };

        var exception = Record.Exception(
            () => OAuthOptionsValidator.Validate(options));

        Assert.Null(exception);
    }

    [Fact]
    public void Validate_WhenEnabledWithoutClients_ShouldThrow()
    {
        var options = new OAuthOptions { Enabled = true };

        Assert.Throws<InvalidOperationException>(
            () => OAuthOptionsValidator.Validate(options));
    }

    [Fact]
    public void Validate_WhenClientConfigurationValid_ShouldSucceed()
    {
        var options = CreateValidOptions();

        var exception = Record.Exception(
            () => OAuthOptionsValidator.Validate(options));

        Assert.Null(exception);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("http://identity.example.com/connect/token")]
    [InlineData("invalid-url")]
    [InlineData("https://user:pass@identity.example.com/token")]
    public void Validate_WhenTokenEndpointInvalid_ShouldThrow(
        string endpoint)
    {
        var options = CreateValidOptions();
        options.Clients["PaymentService"].TokenEndpoint = endpoint;

        Assert.Throws<InvalidOperationException>(
            () => OAuthOptionsValidator.Validate(options));
    }

    [Theory]
    [InlineData("", "secret")]
    [InlineData("client-id", "")]
    [InlineData(" ", "secret")]
    [InlineData("client-id", " ")]
    public void Validate_WhenCredentialsMissing_ShouldThrow(
        string clientId,
        string clientSecret)
    {
        var options = CreateValidOptions();

        options.Clients["PaymentService"].ClientId = clientId;
        options.Clients["PaymentService"].ClientSecret = clientSecret;

        Assert.Throws<InvalidOperationException>(
            () => OAuthOptionsValidator.Validate(options));
    }

    private static OAuthOptions CreateValidOptions()
    {
        return new OAuthOptions
        {
            Enabled = true,
            Clients = new Dictionary<string, OAuthClientOptions>
            {
                ["PaymentService"] = new()
                {
                    ClientId = "payment-client",
                    ClientSecret = "test-secret",
                    TokenEndpoint =
                        "https://identity.example.com/connect/token",
                    Scopes = ["payments.read"]
                }
            }
        };
    }
}
