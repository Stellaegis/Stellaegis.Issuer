using System.Net;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using OpenIddict.Server;
using Stellaegis.Primitives;
using Stellaegis.Primitives.AspNetCore;

namespace Stellaegis.Issuer.Tests;

/// <summary>Records the principal of every question asked of the admissions, so that a test reads what the issuer passed.</summary>
internal sealed class CapturingAdmission : IActorAdmission
{
    public List<ClaimsPrincipal> Asked { get; } = [];

    public ValueTask<Result> AdmitAsync(ClaimsPrincipal principal, CancellationToken cancellationToken)
    {
        lock (Asked)
            Asked.Add(principal);
        return ValueTask.FromResult(Result.Success());
    }
}

/// <summary>
/// What OpenIddict keeps of a claim that has no destination: the ground of <c>:[TAMPON]</c>, which keeps the stamp of
/// the session in the code and the refresh token, and never in a token a client or a service reads. The claim is
/// added by a handler of the test at the authorization only, so that whatever the token requests see of it comes from
/// the token presented. Measured on OpenIddict 7.9.0: the code is a reference, its payload kept encrypted in the store;
/// the refresh token is encrypted itself, and given to the client.
/// </summary>
public sealed class RefreshKeptClaimTests
{
    private const string KeptType = "stellaegis.test_kept";
    private const string KeptValue = "stamp-of-the-session";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task A_claim_without_destination_travels_in_the_code_and_the_refresh_token_and_in_no_token_a_client_reads()
    {
        var builder = IssuerTestHost.Builder();
        builder.Services.AddStellaegisActorAdmission<CapturingAdmission>();
        builder.Services.AddOpenIddict().AddServer(server => server.AddEventHandler<OpenIddictServerEvents.ProcessSignInContext>(handler => handler
            .UseInlineHandler(context =>
            {
                if (context.EndpointType == OpenIddictServerEndpointType.Authorization && context.Principal is { } principal)
                    principal.SetClaim(KeptType, KeptValue);   // no destination given
                return default;
            })
            .SetOrder(int.MinValue + 50_000)
            .SetType(OpenIddictServerHandlerType.Custom)));
        await using var app = await builder.StartAsync(Ct);
        await app.DeclarePublicClientAsync(ct: Ct);
        var asked = app.Services.GetServices<IActorAdmission>().OfType<CapturingAdmission>().Single().Asked;

        var (code, verifier) = await app.AuthorizeAsync("jane", ct: Ct);
        asked.Clear();
        var tokens = await app.ExchangeCodeAsync(code, verifier, ct: Ct);
        Assert.Equal(HttpStatusCode.OK, tokens.Status);
        Assert.Equal(KeptValue, Assert.Single(asked).FindFirst(KeptType)?.Value);            // from the code
        Assert.False(IssuerTestHost.Payload(tokens.AccessToken).TryGetProperty(KeptType, out _));
        Assert.False(IssuerTestHost.Payload(tokens.IdToken).TryGetProperty(KeptType, out _));
        Assert.DoesNotContain(KeptValue, Readable(tokens.RefreshToken), StringComparison.Ordinal);   // the client cannot read it
        Assert.DoesNotContain(KeptValue, Readable(code), StringComparison.Ordinal);

        asked.Clear();
        var refreshed = await app.RefreshAsync(tokens.RefreshToken, ct: Ct);
        Assert.Equal(HttpStatusCode.OK, refreshed.Status);
        Assert.Equal(KeptValue, Assert.Single(asked).FindFirst(KeptType)?.Value);            // from the refresh token
        Assert.False(IssuerTestHost.Payload(refreshed.AccessToken).TryGetProperty(KeptType, out _));

        asked.Clear();
        var again = await app.RefreshAsync(refreshed.RefreshToken, ct: Ct);                  // the refresh token the refresh issued
        Assert.Equal(HttpStatusCode.OK, again.Status);
        Assert.Equal(KeptValue, Assert.Single(asked).FindFirst(KeptType)?.Value);
        Assert.DoesNotContain(KeptValue, again.Body.GetRawText(), StringComparison.Ordinal);
        Assert.DoesNotContain(KeptValue, Readable(again.RefreshToken), StringComparison.Ordinal);

        // What the store keeps of the tokens, the payload of a reference token included, is not readable either.
        using var scope = app.Services.CreateScope();
        var stored = await scope.ServiceProvider.GetRequiredService<IssuerDbContext>().Set<OpenIddictEntityFrameworkCoreToken>()
            .Select(token => new { token.Type, token.Payload, token.ReferenceId })
            .ToListAsync(Ct);
        Assert.Contains(stored, token => token.Type == OpenIddictConstants.TokenTypeIdentifiers.RefreshToken);
        Assert.All(stored, token => Assert.DoesNotContain(KeptValue, Readable(token.Payload ?? ""), StringComparison.Ordinal));
    }

    /// <summary>What anyone holding <paramref name="token"/> reads of it: each segment decoded where it decodes.</summary>
    private static string Readable(string token)
        => string.Join("\n", token.Split('.').Select(segment =>
        {
            try { return System.Text.Encoding.UTF8.GetString(Microsoft.AspNetCore.WebUtilities.Base64UrlTextEncoder.Decode(segment)); }
            catch (FormatException) { return segment; }
        }).Append(token));
}
