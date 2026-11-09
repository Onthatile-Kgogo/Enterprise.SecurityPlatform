using Enterprise.Security.Core.Configuration.JwtConfig;

namespace Enterprise.Security.Core.Tests.Configuration;

public sealed class JwtScopeMappingValidationTests
{
    [Fact]
    public void Validate_AcceptsExplicitScopeMappings()
    {
        var options = CreateOptions();

        options.Providers["primary"].ScopeToPermissions["manage"] =
            ["transactions.read", "transactions.write"];

        JwtAuthenticationOptionsValidator.Validate(options);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("enterprise_security_permission")]
    [InlineData("ENTERPRISE_SECURITY_PERMISSION")]
    public void Validate_RejectsInvalidScopeClaimType(string claimType)
    {
        var options = CreateOptions();
        options.Providers["primary"].ScopeClaimType = claimType;

        Assert.Throws<InvalidOperationException>(() =>
            JwtAuthenticationOptionsValidator.Validate(options));
    }

    [Theory]
    [InlineData("enterprise_security_permission")]
    [InlineData("ENTERPRISE_SECURITY_PERMISSION")]
    public void Validate_RejectsReservedPermissionClaimType(string claimType)
    {
        var options = CreateOptions();
        options.Providers["primary"].PermissionClaimType = claimType;

        Assert.Throws<InvalidOperationException>(() =>
            JwtAuthenticationOptionsValidator.Validate(options));
    }

    [Fact]
    public void Validate_RejectsNullScopeMappings()
    {
        var options = CreateOptions();
        options.Providers["primary"].ScopeToPermissions = null!;

        Assert.Throws<InvalidOperationException>(() =>
            JwtAuthenticationOptionsValidator.Validate(options));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("read write")]
    [InlineData("read\twrite")]
    public void Validate_RejectsInvalidScopeKeys(string scope)
    {
        var options = CreateOptions();

        options.Providers["primary"].ScopeToPermissions[scope] =
            ["transactions.read"];

        Assert.Throws<InvalidOperationException>(() =>
            JwtAuthenticationOptionsValidator.Validate(options));
    }

    [Fact]
    public void Validate_RejectsNullMappedPermissions()
    {
        var options = CreateOptions();
        options.Providers["primary"].ScopeToPermissions["read"] = null!;

        Assert.Throws<InvalidOperationException>(() =>
            JwtAuthenticationOptionsValidator.Validate(options));
    }

    [Fact]
    public void Validate_RejectsEmptyMappedPermissions()
    {
        var options = CreateOptions();
        options.Providers["primary"].ScopeToPermissions["read"] = [];

        Assert.Throws<InvalidOperationException>(() =>
            JwtAuthenticationOptionsValidator.Validate(options));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    public void Validate_RejectsBlankMappedPermissions(string permission)
    {
        var options = CreateOptions();

        options.Providers["primary"].ScopeToPermissions["read"] =
            ["transactions.read", permission];

        Assert.Throws<InvalidOperationException>(() =>
            JwtAuthenticationOptionsValidator.Validate(options));
    }

    [Fact]
    public void Validate_DisabledAuthenticationSkipsScopeValidation()
    {
        var options = CreateOptions();
        options.Enabled = false;
        options.Providers["primary"].ScopeToPermissions = null!;

        JwtAuthenticationOptionsValidator.Validate(options);
    }

    private static JwtAuthenticationOptions CreateOptions()
    {
        return new JwtAuthenticationOptions
        {
            Enabled = true,
            Providers =
            {
                ["primary"] = new JwtProviderOptions
                {
                    Scheme = "PrimaryJwt",
                    Authority = "https://identity.example.com",
                    Audience = "transactions-api"
                }
            }
        };
    }
}