using Enterprise.Security.Core.Abstractions;
using Enterprise.Security.Core.Models;
using Microsoft.Extensions.Caching.Memory;

namespace Enterprise.Security.Authentication.OAuth
{
    internal sealed class MemoryTokenCache : ITokenCache
    {
        private readonly IMemoryCache _cache;

        public MemoryTokenCache(IMemoryCache cache)
        {
            _cache = cache;
        }

        public ValueTask<AccessToken?> GetAsync(string cacheKey, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var key = (typeof(MemoryTokenCache), cacheKey);
            _cache.TryGetValue<AccessToken>(key, out var token);

            return ValueTask.FromResult(token);
        }

        public ValueTask SetAsync(string cacheKey, AccessToken token, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var key = (typeof(MemoryTokenCache), cacheKey);
            _cache.Set(key, token, token.ExpiresAtUtc);

            return ValueTask.CompletedTask;
        }
    }
}