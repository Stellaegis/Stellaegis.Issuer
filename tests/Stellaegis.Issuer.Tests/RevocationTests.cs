using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Stellaegis.Issuer.Client;
using Stellaegis.Primitives.AspNetCore;

namespace Stellaegis.Issuer.Tests;

/// <summary>What revoking does: the store, the event, the source a resource server reads, the admission it keeps.</summary>
public sealed class RevocationTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Revoking_a_subject_announces_each_access_token_and_the_source_lists_it()
    {
        await using var app = await IssuerTestHost.Builder().StartAsync(Ct);
        await app.DeclarePublicClientAsync(ct: Ct);
        var (code, verifier) = await app.AuthorizeAsync("jane", ct: Ct);
        var tokens = await app.ExchangeCodeAsync(code, verifier, ct: Ct);
        var tokenId = IssuerTestHost.Payload(tokens.AccessToken).GetProperty("oi_tkn_id").GetString()!;

        int revoked;
        IReadOnlyCollection<RevokedToken> listed;
        using (var scope = app.Services.CreateScope())
        {
            revoked = await scope.ServiceProvider.GetRequiredService<ITokenRevoker>().RevokeSubjectAsync("jane", Ct);
            listed = await scope.ServiceProvider.GetRequiredService<IRevokedTokensSource>().GetRevokedTokensAsync(Ct);
        }

        Assert.True(revoked >= 2);                                           // the access token and the refresh token, at least
        var announced = Assert.Single(app.Events().Events.OfType<TokenRevokedEvent>());
        Assert.Equal(tokenId, announced.TokenId);
        Assert.Equal("jane", announced.Subject);
        Assert.True(announced.ExpiresAt > announced.OccurredAt);
        Assert.Equal(tokenId, Assert.Single(listed).TokenId);

        var refreshed = await app.RefreshAsync(tokens.RefreshToken, ct: Ct);   // the refresh token is revoked at the store
        Assert.Equal(HttpStatusCode.BadRequest, refreshed.Status);
        Assert.Equal("invalid_grant", refreshed.Error);
    }

    [Fact]
    public async Task The_admission_of_the_issuer_refuses_a_revoked_token_and_the_host_asks_it_at_the_door()
    {
        await using var app = await IssuerTestHost.Builder().StartAsync(Ct);
        await app.DeclarePublicClientAsync(ct: Ct);
        var (code, verifier) = await app.AuthorizeAsync("jane", ct: Ct);
        var tokens = await app.ExchangeCodeAsync(code, verifier, ct: Ct);
        var tokenId = IssuerTestHost.Payload(tokens.AccessToken).GetProperty("oi_tkn_id").GetString()!;
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "jane"), new Claim("oi_tkn_id", tokenId)], "Bearer"));
        var admissions = app.Services.GetRequiredService<IActorAdmissions>();
        var revokedTokens = app.Services.GetRequiredService<RevokedTokens>();

        Assert.True((await admissions.AdmitAsync(principal, Ct)).IsSuccess);

        using (var scope = app.Services.CreateScope())
            Assert.True((await scope.ServiceProvider.GetRequiredService<ITokenRevoker>().RevokeTokenAsync(tokenId, Ct)).IsSuccess);

        var refused = await admissions.AdmitAsync(principal, Ct);           // the issuer in the same process refused it at once
        Assert.True(refused.IsFailure);
        Assert.Equal(IssuerErrors.TokenRevokedCode, refused.Error!.Code);
        Assert.Equal(tokenId, Assert.Single(revokedTokens.Tokens).TokenId);

        revokedTokens.Replace([]);                                           // what a reading of an empty source does
        Assert.True((await admissions.AdmitAsync(principal, Ct)).IsSuccess);
        revokedTokens.Replace(await app.Services.CreateScope().ServiceProvider.GetRequiredService<IRevokedTokensSource>().GetRevokedTokensAsync(Ct));
        Assert.True((await admissions.AdmitAsync(principal, Ct)).IsFailure);

        var unknown = await app.Services.CreateScope().ServiceProvider.GetRequiredService<ITokenRevoker>().RevokeTokenAsync("nowhere", Ct);
        Assert.Equal(IssuerErrors.TokenNotFoundCode, unknown.Error?.Code);
    }

    [Fact]
    public async Task Revoking_an_authorization_ends_the_session_and_leaves_the_others()
    {
        await using var app = await IssuerTestHost.Builder().StartAsync(Ct);
        await app.DeclarePublicClientAsync(ct: Ct);
        var (code1, verifier1) = await app.AuthorizeAsync("jane", ct: Ct);
        var first = await app.ExchangeCodeAsync(code1, verifier1, ct: Ct);
        var (code2, verifier2) = await app.AuthorizeAsync("jane", ct: Ct);
        var second = await app.ExchangeCodeAsync(code2, verifier2, ct: Ct);
        var authorizationId = IssuerTestHost.Payload(first.AccessToken).GetProperty("oi_au_id").GetString()!;

        using (var scope = app.Services.CreateScope())
        {
            var revoked = await scope.ServiceProvider.GetRequiredService<ITokenRevoker>().RevokeAuthorizationAsync(authorizationId, Ct);
            Assert.True(revoked.IsSuccess, revoked.Error?.ToString());
            Assert.True(revoked.Value >= 2);
        }

        Assert.Equal(HttpStatusCode.BadRequest, (await app.RefreshAsync(first.RefreshToken, ct: Ct)).Status);
        Assert.Equal(HttpStatusCode.OK, (await app.RefreshAsync(second.RefreshToken, ct: Ct)).Status);
    }
}
