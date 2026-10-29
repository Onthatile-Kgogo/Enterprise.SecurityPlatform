using Enterprise.Security.Core.Models;

namespace Enterprise.Security.Core.Abstractions
{
    public interface IClientCredentialProvider
    {
        ValueTask<ClientCredentials> GetCredentialsAsync(string clientName, CancellationToken cancellationToken = default);
    }
}
