using Microsoft.AspNetCore.Authentication;

namespace Enterprise.Security.Authentication.Handlers;

public sealed class MultiProviderJwtOptions : AuthenticationSchemeOptions
{
    public string[] ProviderSchemes { get; set; } = [];
}