using Enterprise.Security.Core.Configuration.JwtConfig;

namespace Enterprise.Security.Core.Tests.Configuration;

public sealed class JwtAuthenticationOptionsValidatorTests
{
    [Fact]
    public void Validate_WhenDisabled_ShouldSucceed()
    {
        var options = new JwtAuthenticationOptions
        {
            Enabled = false
        };

        var exception = Record.Exception(() => JwtAuthenticationOptionsValidator.Validate(options));

        Assert.Null(exception);
    }

    [Fact]
    public void Validate_WhenEnabledWithoutProviders_ShouldThrow()
    {
        var options = new JwtAuthenticationOptions
        {
            Enabled = true
        };

        Assert.Throws<InvalidOperationException>(() => JwtAuthenticationOptionsValidator.Validate(options));
    }

    [Fact]
    public void Validate_WhenConfigurationValid_ShouldSucceed()
    {
        var options = CreateValidOptions();
        var exception = Record.Exception(() => JwtAuthenticationOptionsValidator.Validate(options));

        Assert.Null(exception);
    }

    [Fact]
    public void Validate_WhenSchemesDuplicated_ShouldThrow()
    {
        var options = CreateValidOptions();

        options.Providers["External"] = new JwtProviderOptions
        {
            Scheme = "InternalBearer",
            Authority = "https://external.example.com",
            Audience = "enterprise-api"
        };

        Assert.Throws<InvalidOperationException>(() => JwtAuthenticationOptionsValidator.Validate(options));
    }

    [Theory]
    [InlineData("")]
    [InlineData("http://identity.example.com")]
    [InlineData("invalid-url")]
    [InlineData("https://user:pass@identity.example.com")]
    public void Validate_WhenAuthorityInvalid_ShouldThrow(string authority)
    {
        var options = CreateValidOptions();
        options.Providers["Internal"].Authority = authority;

        Assert.Throws<InvalidOperationException>(() => JwtAuthenticationOptionsValidator.Validate(options));
    }

    [Fact]
    public void Validate_WhenAudienceMissing_ShouldThrow()
    {
        var options = CreateValidOptions();
        options.Providers["Internal"].Audience = "";

        Assert.Throws<InvalidOperationException>(() => JwtAuthenticationOptionsValidator.Validate(options));
    }

    [Fact]
    public void Validate_WhenHttpsMetadataDisabled_ShouldThrow()
    {
        var options = CreateValidOptions();
        options.Providers["Internal"].RequireHttpsMetadata = false;

        Assert.Throws<InvalidOperationException>(() => JwtAuthenticationOptionsValidator.Validate(options));
    }

    [Theory]
    [InlineData("", "permission")]
    [InlineData("role", "")]
    public void Validate_WhenClaimMappingMissing_ShouldThrow(string roleClaimType, string permissionClaimType)
    {
        var options = CreateValidOptions();

        options.Providers["Internal"].RoleClaimType = roleClaimType;
        options.Providers["Internal"].PermissionClaimType = permissionClaimType;

        Assert.Throws<InvalidOperationException>(() => JwtAuthenticationOptionsValidator.Validate(options));
    }

    private static JwtAuthenticationOptions CreateValidOptions()
    {
        return new JwtAuthenticationOptions
        {
            Enabled = true,
            Providers = new Dictionary<string, JwtProviderOptions>
            {
                ["Internal"] = new()
                {
                    Scheme = "InternalBearer",
                    Authority = "https://identity.example.com",
                    Audience = "enterprise-api"
                }
            }
        };
    }
}
