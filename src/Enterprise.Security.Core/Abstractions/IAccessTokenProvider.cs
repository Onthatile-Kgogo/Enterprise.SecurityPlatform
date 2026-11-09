using Enterprise.Security.Core.Models;

namespace Enterprise.Security.Core.Abstractions
{
    public interface IAccessTokenProvider
    {
        ValueTask<AccessToken> GetAccessTokenAsync(string clientName, CancellationToken cancellationToken = default);
    }
}