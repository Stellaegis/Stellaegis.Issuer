using System.Collections.Concurrent;
using System.Security.Claims;
using Stellaegis.Primitives;
using Stellaegis.Primitives.AspNetCore;

namespace Stellaegis.Issuer.Client;

/// <summary>The errors this package answers, each with the code that lets the caller recognize it.</summary>
public static class IssuerClientErrors
{
    /// <summary>The code of <see cref="TokenRevoked"/>: the token the principal carries was revoked.</summary>
    public const string TokenRevokedCode = "Token.Revoked";

    /// <summary>The token the principal carries was revoked.</summary>
    public static Error TokenRevoked { get; } = Error.Unauthorized(TokenRevokedCode, "The token was revoked.");
}

/// <summary>An access token revoked before its expiration, as a resource server reads it.</summary>
/// <param name="TokenId">The id of the token, which its <c>oi_tkn_id</c> claim carries.</param>
/// <param name="ExpiresAt">When the token expires anyway.</param>
public sealed record RevokedToken(string TokenId, DateTimeOffset ExpiresAt);

/// <summary>
/// Where a resource server reads the access tokens revoked before their expiration: the token store, on a host
/// that holds the issuer (<c>Stellaegis.Issuer</c> registers it); the issuer's route over HTTP, on a resource
/// server apart (<see cref="ServiceCollectionExtensions.AddStellaegisIssuerClient(Microsoft.Extensions.DependencyInjection.IServiceCollection, Microsoft.Extensions.Configuration.IConfiguration, string)"/>).
/// </summary>
public interface IRevokedTokensSource
{
    /// <summary>The access tokens revoked and not yet expired.</summary>
    Task<IReadOnlyCollection<RevokedToken>> GetRevokedTokensAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// The access tokens revoked before their expiration, as a resource server keeps them in memory to refuse them on
/// every request without a round trip: the <see cref="IActorAdmission"/> of the issuer, registered beside the
/// admissions of the other modules by <c>AddStellaegisIssuerAdmission()</c>. Filled from
/// <see cref="IRevokedTokensSource"/> when the host starts and then periodically; kept current in between by the
/// host, which calls <see cref="Revoke"/> from its subscription to the <c>TokenRevoked</c> event of the issuer —
/// and by the issuer itself when both are in one process. An expired token leaves the set by itself.
/// </summary>
public sealed class RevokedTokens(TimeProvider clock) : IActorAdmission
{
    /// <summary>The claim OpenIddict stamps every token with, carrying the token's id.</summary>
    public const string TokenIdClaim = "oi_tkn_id";

    private volatile ConcurrentDictionary<string, DateTimeOffset> _revoked = new(StringComparer.Ordinal);

    /// <summary>Whether the token — the <c>oi_tkn_id</c> claim — is revoked and not yet expired.</summary>
    public bool IsRevoked(string tokenId)
        => !string.IsNullOrWhiteSpace(tokenId) && _revoked.TryGetValue(tokenId, out var expiresAt) && expiresAt > clock.GetUtcNow();

    /// <summary>Refuses the token from now on, until it expires: what the host calls from its subscription to the <c>TokenRevoked</c> event.</summary>
    public void Revoke(string tokenId, DateTimeOffset expiresAt)
    {
        Guard.NotWhiteSpace(tokenId);
        if (expiresAt > clock.GetUtcNow())
            _revoked[tokenId] = expiresAt;
    }

    /// <summary>Replaces every token by <paramref name="tokens"/>, in one move: what a reading of the source does.</summary>
    public void Replace(IEnumerable<RevokedToken> tokens)
    {
        Guard.NotNull(tokens);
        var now = clock.GetUtcNow();
        var replacement = new ConcurrentDictionary<string, DateTimeOffset>(StringComparer.Ordinal);
        foreach (var token in tokens)
        {
            if (!string.IsNullOrWhiteSpace(token.TokenId) && token.ExpiresAt > now)
                replacement[token.TokenId] = token.ExpiresAt;
        }
        _revoked = replacement;
    }

    /// <summary>The tokens revoked and not yet expired, as a snapshot.</summary>
    public IReadOnlyCollection<RevokedToken> Tokens
    {
        get
        {
            var now = clock.GetUtcNow();
            return _revoked.Where(pair => pair.Value > now).Select(pair => new RevokedToken(pair.Key, pair.Value)).ToList();
        }
    }

    /// <summary>Refuses, with <see cref="IssuerClientErrors.TokenRevoked"/>, a principal whose token is revoked.</summary>
    public ValueTask<Result> AdmitAsync(ClaimsPrincipal principal, CancellationToken cancellationToken)
        => ValueTask.FromResult(Guard.NotNull(principal).FindFirst(TokenIdClaim)?.Value is { } tokenId && IsRevoked(tokenId)
            ? Result.Failure(IssuerClientErrors.TokenRevoked)
            : Result.Success());
}
