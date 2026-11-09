using Enterprise.Security.Core.Models;

namespace Enterprise.Security.Core.Abstractions
{
    public interface ITokenCache
    {
        ValueTask<AccessToken?> GetAsync(string cacheKey, CancellationToken cancellationToken = default);
        ValueTask SetAsync(string cacheKey, AccessToken token, CancellationToken cancellationToken = default);
    }
}