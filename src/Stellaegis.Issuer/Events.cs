using Stellaegis.Primitives;

namespace Stellaegis.Issuer;

/// <summary>
/// Published when an access token is revoked before its expiration — one event per token. A resource server that
/// admits actors refuses the token from then on, without waiting for its next reading of the revoked tokens; the
/// host connects the subscription. The durable half is the token store, which the readings re-sync.
/// </summary>
public sealed record TokenRevokedEvent : IEvent
{
    /// <inheritdoc/>
    public required DateTimeOffset OccurredAt { get; init; }

    /// <summary>The id of the token, which its <c>oi_tkn_id</c> claim carries.</summary>
    public required string TokenId { get; init; }

    /// <summary>The subject the token was issued to: a person's <c>sub</c>, or a client's id.</summary>
    public required string Subject { get; init; }

    /// <summary>When the token expires anyway, after which refusing it is pointless.</summary>
    public required DateTimeOffset ExpiresAt { get; init; }
}
