using System.Net;
using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using Stellaegis.Primitives;
using Stellaegis.Primitives.AspNetCore;

namespace Stellaegis.Issuer.Tests;

/// <summary>
/// Holds the stamp of every subject as the accounts would, and refuses a token request whose kept stamp is not the
/// account's — what the admission of Stellaegis.Identity does, here without the accounts.
/// </summary>
internal sealed class StampHolding : IActorAdmission
{
    public Dictionary<string, string> Current { get; } = new(StringComparer.Ordinal);

    public ValueTask<Result> AdmitAsync(ClaimsPrincipal principal, CancellationToken cancellationToken)
    {
        if (principal.FindFirst(SessionClaims.TokenRequest) is null)
            return ValueTask.FromResult(Result.Success());
        var kept = principal.FindFirst(SessionClaims.SecurityStamp)?.Value;
        var current = Current.GetValueOrDefault(principal.FindFirst(OpenIddictConstants.Claims.Subject)?.Value ?? "");
        return ValueTask.FromResult(kept is not null && kept == current
            ? Result.Success()
            : Result.Failure(Error.Unauthorized("Session.Stale", "The session this token was issued for no longer holds.")));
    }
}

/// <summary>
/// The security stamp of the session, kept by the issuer for the token requests, and the mark it gives the admissions
/// at each of them (<c>:[TAMPON]</c>). The issuer carries the stamp and reads no account: the admissions decide.
/// </summary>
public sealed class SessionStampTests
{
    private const string Stamp = "stamp-of-the-session";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task The_stamp_of_the_session_reaches_the_admissions_at_every_token_request_under_its_mark_and_no_token_a_client_reads()
    {
        var builder = IssuerTestHost.Builder();
        builder.Services.AddStellaegisActorAdmission<CapturingAdmission>();
        await using var app = await builder.StartAsync(Ct);
        await app.DeclarePublicClientAsync(ct: Ct);
        var asked = app.Services.GetServices<IActorAdmission>().OfType<CapturingAdmission>().Single().Asked;

        var (code, verifier) = await app.AuthorizeAsync("jane", ct: Ct, stamp: Stamp);
        Assert.Null(Assert.Single(asked).FindFirst(SessionClaims.TokenRequest));                // the authorization is no token request

        asked.Clear();
        var tokens = await app.ExchangeCodeAsync(code, verifier, ct: Ct);
        Assert.Equal(HttpStatusCode.OK, tokens.Status);
        var atExchange = Assert.Single(asked);
        Assert.Equal(SessionClaims.AuthorizationCodeRequest, Assert.Single(atExchange.FindAll(SessionClaims.TokenRequest)).Value);
        Assert.Equal(Stamp, atExchange.FindFirst(SessionClaims.SecurityStamp)?.Value);
        AssertInNoTokenAClientReads(tokens);

        foreach (var _ in Enumerable.Range(0, 2))   // a refresh, then the refresh token it issued
        {
            asked.Clear();
            tokens = await app.RefreshAsync(tokens.RefreshToken, ct: Ct);
            Assert.Equal(HttpStatusCode.OK, tokens.Status);
            var atRefresh = Assert.Single(asked);
            Assert.Equal(SessionClaims.RefreshTokenRequest, Assert.Single(atRefresh.FindAll(SessionClaims.TokenRequest)).Value);
            Assert.Equal(Stamp, atRefresh.FindFirst(SessionClaims.SecurityStamp)?.Value);
            AssertInNoTokenAClientReads(tokens);
        }
    }

    [Fact]
    public async Task A_session_without_stamp_gives_the_admissions_the_mark_and_no_stamp()
    {
        var builder = IssuerTestHost.Builder();
        builder.Services.AddStellaegisActorAdmission<CapturingAdmission>();
        await using var app = await builder.StartAsync(Ct);
        await app.DeclarePublicClientAsync(ct: Ct);
        var asked = app.Services.GetServices<IActorAdmission>().OfType<CapturingAdmission>().Single().Asked;

        var (code, verifier) = await app.AuthorizeAsync("jane", ct: Ct);
        asked.Clear();
        Assert.Equal(HttpStatusCode.OK, (await app.ExchangeCodeAsync(code, verifier, ct: Ct)).Status);

        var atExchange = Assert.Single(asked);
        Assert.NotNull(atExchange.FindFirst(SessionClaims.TokenRequest));
        Assert.Null(atExchange.FindFirst(SessionClaims.SecurityStamp));
    }

    [Fact]
    public async Task A_mark_the_token_came_with_is_replaced_by_the_issuers_own()
    {
        var builder = IssuerTestHost.Builder();
        builder.Services.AddStellaegisActorAdmission<CapturingAdmission>();
        builder.Services.AddOpenIddict().AddServer(server => server.AddEventHandler<OpenIddictServerEvents.ProcessSignInContext>(handler => handler
            .UseInlineHandler(context =>
            {
                if (context.EndpointType == OpenIddictServerEndpointType.Authorization && context.Principal is { } principal)
                    principal.SetClaim(SessionClaims.TokenRequest, "forged");   // kept in the code, as the stamp is
                return default;
            })
            .SetOrder(int.MinValue + 50_000)
            .SetType(OpenIddictServerHandlerType.Custom)));
        await using var app = await builder.StartAsync(Ct);
        await app.DeclarePublicClientAsync(ct: Ct);
        var asked = app.Services.GetServices<IActorAdmission>().OfType<CapturingAdmission>().Single().Asked;

        var (code, verifier) = await app.AuthorizeAsync("jane", ct: Ct, stamp: Stamp);
        asked.Clear();
        var tokens = await app.ExchangeCodeAsync(code, verifier, ct: Ct);
        Assert.Equal(HttpStatusCode.OK, tokens.Status);
        Assert.Equal(SessionClaims.AuthorizationCodeRequest, Assert.Single(Assert.Single(asked).FindAll(SessionClaims.TokenRequest)).Value);

        asked.Clear();
        Assert.Equal(HttpStatusCode.OK, (await app.RefreshAsync(tokens.RefreshToken, ct: Ct)).Status);
        Assert.Equal(SessionClaims.RefreshTokenRequest, Assert.Single(Assert.Single(asked).FindAll(SessionClaims.TokenRequest)).Value);
    }

    [Fact]
    public async Task A_stamp_changed_since_the_login_refuses_the_refresh_with_invalid_grant()
    {
        var builder = IssuerTestHost.Builder();
        builder.Services.AddSingleton<StampHolding>();
        builder.Services.AddStellaegisActorAdmission(services => services.GetRequiredService<StampHolding>());
        await using var app = await builder.StartAsync(Ct);
        await app.DeclarePublicClientAsync(ct: Ct);
        var accounts = app.Services.GetRequiredService<StampHolding>();
        accounts.Current["jane"] = Stamp;

        var (code, verifier) = await app.AuthorizeAsync("jane", ct: Ct, stamp: Stamp);
        var tokens = await app.ExchangeCodeAsync(code, verifier, ct: Ct);
        Assert.Equal(HttpStatusCode.OK, tokens.Status);
        tokens = await app.RefreshAsync(tokens.RefreshToken, ct: Ct);
        Assert.Equal(HttpStatusCode.OK, tokens.Status);

        accounts.Current["jane"] = "stamp-renewed";   // an address changed, a second factor disabled: no event needed
        var refused = await app.RefreshAsync(tokens.RefreshToken, ct: Ct);
        Assert.Equal("invalid_grant", refused.Error);
    }

    [Fact]
    public void The_copy_given_the_admissions_leaves_the_principal_of_the_token_as_it_was()
    {
        var identity = new ClaimsIdentity([new Claim("sub", "jane"), new Claim(SessionClaims.TokenRequest, "forged")], "test");
        var principal = new ClaimsPrincipal(identity);

        var marked = RefreshAdmissionHandler.Marked(principal, SessionClaims.RefreshTokenRequest);

        Assert.Equal(SessionClaims.RefreshTokenRequest, Assert.Single(marked.FindAll(SessionClaims.TokenRequest)).Value);
        Assert.Equal("jane", marked.FindFirst("sub")?.Value);
        Assert.Equal("forged", Assert.Single(principal.FindAll(SessionClaims.TokenRequest)).Value);
        Assert.Equal(2, identity.Claims.Count());
    }

    private static void AssertInNoTokenAClientReads(TokenResponse tokens)
    {
        foreach (var jwt in new[] { tokens.AccessToken, tokens.IdToken }.Where(token => token is not null))
        {
            var payload = IssuerTestHost.Payload(jwt!);
            Assert.False(payload.TryGetProperty(SessionClaims.SecurityStamp, out _));
            Assert.False(payload.TryGetProperty(SessionClaims.TokenRequest, out _));
        }
        Assert.DoesNotContain(Stamp, tokens.Body.GetRawText(), StringComparison.Ordinal);
    }
}
