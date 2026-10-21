using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using Stellaegis.Issuer.Client;
using Stellaegis.Primitives;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Stellaegis.Issuer;

/// <summary>
/// Revokes what the issuer issued, at the store, and announces each access token revoked before its expiration
/// as a <see cref="TokenRevokedEvent"/> — the store is the durable half, which the readings of
/// <see cref="IRevokedTokensSource"/> (<c>Stellaegis.Issuer.Client</c>) re-sync; the event is the shortcut. The host calls it from its subscription
/// to the <c>UserBlocked</c> event of the accounts, an administrator from the <c>tokens.revoke</c> route, the person
/// from their sessions page; the caller owns the decision, this only performs it.
/// </summary>
public interface ITokenRevoker
{
    /// <summary>
    /// Revokes every authorization and every token of <paramref name="subject"/> — a person's <c>sub</c>, a
    /// client's id —: what blocking an account calls for. Returns how many tokens were revoked.
    /// </summary>
    Task<int> RevokeSubjectAsync(string subject, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes the authorization <paramref name="authorizationId"/> — a session — and every token it issued.
    /// Returns how many tokens were revoked, or <see cref="IssuerErrors.TokenNotFound"/> when no authorization has
    /// that id.
    /// </summary>
    Task<Result<int>> RevokeAuthorizationAsync(string authorizationId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes the one token <paramref name="tokenId"/>, whatever its kind. <see cref="IssuerErrors.TokenNotFound"/>
    /// when no token has that id.
    /// </summary>
    Task<Result> RevokeTokenAsync(string tokenId, CancellationToken cancellationToken = default);
}

internal sealed class TokenRevoker(
    IOpenIddictTokenManager tokens,
    IOpenIddictAuthorizationManager authorizations,
    IEventPublisher events,
    IServiceProvider services,
    TimeProvider clock,
    ILogger<TokenRevoker> logger) : ITokenRevoker
{
    public async Task<int> RevokeSubjectAsync(string subject, CancellationToken cancellationToken = default)
    {
        Guard.NotWhiteSpace(subject);
        await foreach (var authorization in authorizations.FindBySubjectAsync(subject, cancellationToken).ConfigureAwait(false))
            await authorizations.TryRevokeAsync(authorization, cancellationToken).ConfigureAwait(false);

        var revoked = 0;
        await foreach (var token in tokens.FindBySubjectAsync(subject, cancellationToken).ConfigureAwait(false))
        {
            if (await RevokeAndAnnounceAsync(token, cancellationToken).ConfigureAwait(false))
                revoked++;
        }
        logger.LogInformation("Revoked every token of subject {Subject}: {Count}", subject, revoked);
        return revoked;
    }

    public async Task<Result<int>> RevokeAuthorizationAsync(string authorizationId, CancellationToken cancellationToken = default)
    {
        Guard.NotWhiteSpace(authorizationId);
        var authorization = await authorizations.FindByIdAsync(authorizationId, cancellationToken).ConfigureAwait(false);
        if (authorization is null)
            return Result.Failure<int>(IssuerErrors.TokenNotFound);
        await authorizations.TryRevokeAsync(authorization, cancellationToken).ConfigureAwait(false);

        var revoked = 0;
        await foreach (var token in tokens.FindByAuthorizationIdAsync(authorizationId, cancellationToken).ConfigureAwait(false))
        {
            if (await RevokeAndAnnounceAsync(token, cancellationToken).ConfigureAwait(false))
                revoked++;
        }
        logger.LogInformation("Revoked the authorization {AuthorizationId} and its tokens: {Count}", authorizationId, revoked);
        return Result.Success(revoked);
    }

    public async Task<Result> RevokeTokenAsync(string tokenId, CancellationToken cancellationToken = default)
    {
        Guard.NotWhiteSpace(tokenId);
        var token = await tokens.FindByIdAsync(tokenId, cancellationToken).ConfigureAwait(false);
        if (token is null)
            return Result.Failure(IssuerErrors.TokenNotFound);
        await RevokeAndAnnounceAsync(token, cancellationToken).ConfigureAwait(false);
        return Result.Success();
    }

    /// <summary>Revokes the token when it was still valid, and announces it when it is an access token not yet expired. Whether something was revoked.</summary>
    private async Task<bool> RevokeAndAnnounceAsync(object token, CancellationToken cancellationToken)
    {
        if (await tokens.GetStatusAsync(token, cancellationToken).ConfigureAwait(false) != Statuses.Valid)
            return false;
        if (!await tokens.TryRevokeAsync(token, cancellationToken).ConfigureAwait(false))
            return false;

        if (await tokens.GetTypeAsync(token, cancellationToken).ConfigureAwait(false) != TokenTypeIdentifiers.AccessToken)
            return true;
        var id = await tokens.GetIdAsync(token, cancellationToken).ConfigureAwait(false);
        var subject = await tokens.GetSubjectAsync(token, cancellationToken).ConfigureAwait(false);
        var expiresAt = await tokens.GetExpirationDateAsync(token, cancellationToken).ConfigureAwait(false);
        if (id is null || subject is null || expiresAt is null || expiresAt <= clock.GetUtcNow())
            return true;

        // A host that holds the admission in the same process refuses the token at once, bus or no bus.
        services.GetService<RevokedTokens>()?.Revoke(id, expiresAt.Value);
        await events.PublishAsync(new TokenRevokedEvent
        {
            OccurredAt = clock.GetUtcNow(),
            TokenId = id,
            Subject = subject,
            ExpiresAt = expiresAt.Value,
        }, cancellationToken).ConfigureAwait(false);
        return true;
    }
}

/// <summary>The source over the token store, for a host that holds the issuer.</summary>
internal sealed class LocalRevokedTokensSource(IssuerDbContext db, TimeProvider clock) : IRevokedTokensSource
{
    public async Task<IReadOnlyCollection<RevokedToken>> GetRevokedTokensAsync(CancellationToken cancellationToken = default)
    {
        var now = clock.GetUtcNow().UtcDateTime;
        var rows = await db.Set<OpenIddictEntityFrameworkCoreToken>()
            .Where(token => token.Status == Statuses.Revoked
                && token.Type == TokenTypeIdentifiers.AccessToken
                && token.ExpirationDate != null
                && token.ExpirationDate > now)
            .Select(token => new { token.Id, token.ExpirationDate })
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        return rows
            .Where(row => row.Id is not null && row.ExpirationDate is not null)
            .Select(row => new RevokedToken(row.Id!, new DateTimeOffset(DateTime.SpecifyKind(row.ExpirationDate!.Value, DateTimeKind.Utc))))
            .ToList();
    }
}
