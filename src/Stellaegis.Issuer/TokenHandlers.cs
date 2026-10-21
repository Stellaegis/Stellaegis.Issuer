using System.Security.Claims;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using Stellaegis.Primitives.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Stellaegis.Issuer;

/// <summary>
/// Issues the token of a <c>client_credentials</c> request: a principal whose <c>sub</c> is the client id, with the
/// scopes requested and, as audiences, the same values — a scope is the name of a module. Every claim goes to the
/// access token only; there is no identity token for a client.
/// </summary>
internal sealed class ClientCredentialsTokenHandler : IOpenIddictServerHandler<OpenIddictServerEvents.HandleTokenRequestContext>
{
    /// <summary>The authentication type of the identities OpenIddict signs.</summary>
    internal const string AuthenticationType = "AuthenticationTypes.Federation";

    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<OpenIddictServerEvents.HandleTokenRequestContext>()
            .UseSingletonHandler<ClientCredentialsTokenHandler>()
            .SetOrder(int.MinValue + 100_000)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(OpenIddictServerEvents.HandleTokenRequestContext context)
    {
        if (!context.Request.IsClientCredentialsGrantType())
            return default;

        var identity = new ClaimsIdentity(AuthenticationType, Claims.Name, Claims.Role);
        identity.SetClaim(Claims.Subject, context.Request.ClientId!);
        identity.SetClaim(Claims.ClientId, context.Request.ClientId!);
        var scopes = context.Request.GetScopes();
        identity.SetScopes(scopes);
        identity.SetResources(scopes);
        identity.SetDestinations(_ => [Destinations.AccessToken]);
        context.Principal = new ClaimsPrincipal(identity);
        return default;
    }
}

/// <summary>
/// Asks the admissions of the host whether the subject of a code or a refresh token is still admitted before a
/// new token is issued — an account blocked since, a session revoked. OpenIddict checks the token; it does not
/// know the accounts, and the issuer does not either: the host's admissions do. A refusal answers
/// <c>invalid_grant</c> with the reason. A <c>client_credentials</c> request carries no person and is untouched.
/// </summary>
internal sealed class RefreshAdmissionHandler(IActorAdmissions admissions, ILogger<RefreshAdmissionHandler> logger)
    : IOpenIddictServerHandler<OpenIddictServerEvents.HandleTokenRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<OpenIddictServerEvents.HandleTokenRequestContext>()
            .UseScopedHandler<RefreshAdmissionHandler>()
            .SetOrder(int.MaxValue - 100_000)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(OpenIddictServerEvents.HandleTokenRequestContext context)
    {
        if (!context.Request.IsRefreshTokenGrantType() && !context.Request.IsAuthorizationCodeGrantType())
            return;
        if (context.Principal is not { } principal)
            return;

        var admitted = await admissions.AdmitAsync(principal, context.CancellationToken).ConfigureAwait(false);
        if (admitted.IsFailure)
        {
            logger.LogWarning("Token exchange refused for subject {Subject}: {Code}", principal.GetClaim(Claims.Subject), admitted.Error!.Code);
            context.Reject(error: Errors.InvalidGrant, description: admitted.Error.Message);
        }
    }
}
