namespace Enterprise.Security.Core.Models
{
    public sealed class AccessToken
    {
        public AccessToken(string value, DateTimeOffset expiresAtUtc)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(value);

            Value = value;
            ExpiresAtUtc = expiresAtUtc.ToUniversalTime();
        }

        public string Value { get; }
        public DateTimeOffset ExpiresAtUtc { get; }
    }
}