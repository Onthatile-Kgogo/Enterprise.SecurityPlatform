
using Enterprise.Security.Core.Configuration;
using Enterprise.Security.Core.Configuration.AuthorizationConfig;

namespace Enterprise.Security.Core.Tests.Configuration;

public sealed class SecurityAuthorizationOptionsValidatorTests
{
    [Fact]
    public void Validate_WhenDisabled_ShouldSucceed()
    {
        var options = new SecurityAuthorizationOptions
        {
            Enabled = false
        };
        var exception = Record.Exception(() => SecurityAuthorizationOptionsValidator.Validate(options));

        Assert.Null(exception);
    }

    [Fact]
    public void Validate_WhenValid_ShouldSucceed()
    {
        var options = CreateValidOptions();
        var exception = Record.Exception(() => SecurityAuthorizationOptionsValidator.Validate(options));

        Assert.Null(exception);
    }

    [Fact]
    public void Validate_WhenPolicyNameEmpty_ShouldThrow()
    {
        var options = CreateValidOptions();
        options.Policies[""] = new AuthorizationPolicyOptions();

        Assert.Throws<InvalidOperationException>(() => SecurityAuthorizationOptionsValidator.Validate(options));
    }

    [Fact]
    public void Validate_WhenPermissionEmpty_ShouldThrow()
    {
        var options = CreateValidOptions();
        options.Policies["ApprovePayments"].RequiredPermissions.Add("");

        Assert.Throws<InvalidOperationException>(() => SecurityAuthorizationOptionsValidator.Validate(options));
    }

    [Fact]
    public void Validate_WhenRoleGroupEmpty_ShouldThrow()
    {
        var options = CreateValidOptions();
        options.Policies["ApprovePayments"].RoleGroups.Add([]);

        Assert.Throws<InvalidOperationException>(() => SecurityAuthorizationOptionsValidator.Validate(options));
    }

    [Fact]
    public void Validate_WhenReferencedPolicyMissing_ShouldThrow()
    {
        var options = CreateValidOptions();
        options.Policies["ApprovePayments"].RequiredPolicies.Add("UnknownPolicy");

        Assert.Throws<InvalidOperationException>(() => SecurityAuthorizationOptionsValidator.Validate(options));
    }

    [Fact]
    public void Validate_WhenPoliciesCircular_ShouldThrow()
    {
        var options = CreateValidOptions();

        options.Policies["ApprovePayments"].RequiredPolicies.Add("ReviewPayments");
        options.Policies["ReviewPayments"] = new AuthorizationPolicyOptions
        {
            RequiredPolicies = ["ApprovePayments"]
        };

        Assert.Throws<InvalidOperationException>(() => SecurityAuthorizationOptionsValidator.Validate(options));
    }


    [Fact]
    public void Validate_WhenPolicyEmpty_ShouldThrow()
    {
        var options = CreateValidOptions();

        options.Policies["EmptyPolicy"] =
            new AuthorizationPolicyOptions();

        Assert.Throws<InvalidOperationException>(
            () => SecurityAuthorizationOptionsValidator.Validate(options));
    }

    [Fact]
    public void Validate_WhenPolicyContainsOnlyReferencedPolicy_ShouldSucceed()
    {
        var options = CreateValidOptions();

        options.Policies["PaymentReview"] =
            new AuthorizationPolicyOptions
            {
                RequiredPolicies = ["ApprovePayments"]
            };

        var exception = Record.Exception(
            () => SecurityAuthorizationOptionsValidator.Validate(options));

        Assert.Null(exception);
    }


    private static SecurityAuthorizationOptions CreateValidOptions()
    {
        return new SecurityAuthorizationOptions
        {
            Enabled = true,
            Policies = new Dictionary<string, AuthorizationPolicyOptions>
            {
                ["ApprovePayments"] = new()
                {
                    RequiredPermissions = ["payments.read", "payments.approve"],
                    RoleGroups = [["Manager", "Supervisor"], ["Finance"]]
                }
            }
        };
    }
}
