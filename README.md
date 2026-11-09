# Enterprise Security Platform

`Enterprise.Security` is a single NuGet package for .NET 10 ASP.NET Core applications. It validates incoming JWT bearer tokens, applies authorization policies, and acquires access tokens for outbound service-to-service calls.

## Features

- JWT bearer authentication with support for multiple trusted identity providers and provider-specific claim mapping.
- Role-, permission-, and policy-based authorization, including explicit scope-to-permission mapping.
- OAuth 2.0 client credentials with in-memory token caching.

## Install

Download `Enterprise.Security.1.0.0.nupkg` from [GitHub Releases](https://github.com/Onthatile-Kgogo/Enterprise.SecurityPlatform/releases) and place it in a local folder, such as `C:\NuGet\Local`. Add this reference to your .NET 10 ASP.NET Core project's `.csproj`:

```xml
<ItemGroup>
    <PackageReference Include="Enterprise.Security" Version="1.0.0" />
</ItemGroup>
```

From the consuming project's directory, restore from the local folder and NuGet.org:

```powershell
dotnet restore --source C:\NuGet\Local --source https://api.nuget.org/v3/index.json
```

## Configure JWT authentication and authorization

In `Program.cs`, register the package and add authentication before authorization:

```csharp
using Enterprise.Security.AspNetCore.Extensions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEnterpriseSecurity(builder.Configuration);

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/reports", () => Results.Ok())
    .RequireAuthorization("ReadReports");

app.Run();
```

Add the following to `appsettings.json`. Replace `Authority` and `Audience` with the values configured for your API by your identity provider. Adjust `ScopeClaimType` if your provider uses a different claim, such as `scp`.

```json
{
  "EnterpriseSecurity": {
    "Authentication": {
      "Enabled": true,
      "Providers": {
        "Primary": {
          "Scheme": "Primary",
          "Authority": "https://identity.example.com",
          "Audience": "reports-api",
          "RequireHttpsMetadata": true,
          "ScopeClaimType": "scope",
          "ScopeToPermissions": {
            "reports.read": ["reports.read"]
          }
        }
      }
    },
    "Authorization": {
      "Enabled": true,
      "Policies": {
        "ReadReports": {
          "RequiredPermissions": ["reports.read"]
        }
      }
    }
  }
}
```

For this endpoint, a missing or invalid token returns `401`. A valid token without the `reports.read` permission returns `403`.

## Configure outbound OAuth 2.0

For service-to-service calls, enable `EnterpriseSecurity:OAuth` and add a named entry under `Clients`. Configure `ClientId`, `TokenEndpoint`, and `Scopes` for that client. Supply `ClientSecret` through a secret store or environment configuration. For a client named `Reporting`, the environment variable is `EnterpriseSecurity__OAuth__Clients__Reporting__ClientSecret`.

## Build, test, and pack

From the repository root with the .NET 10 SDK installed:

```powershell
dotnet build -c Release
dotnet test -c Release
dotnet pack .\packaging\Enterprise.Security\Enterprise.Security.Packaging.csproj -c Release -o .\artifacts\nuget
```

See the [solution architecture](https://github.com/Onthatile-Kgogo/Enterprise.SecurityPlatform/blob/main/docs/architecture/Solution_Architecture.md) and [requirements](https://github.com/Onthatile-Kgogo/Enterprise.SecurityPlatform/blob/main/docs/requirements/Requirements_and_Objectives.md) for design details.

## License

[MIT](https://github.com/Onthatile-Kgogo/Enterprise.SecurityPlatform/blob/main/LICENSE)
