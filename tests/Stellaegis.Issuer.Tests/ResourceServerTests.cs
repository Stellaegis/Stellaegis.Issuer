using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Server;
using Stellaegis.Issuer.Client;

namespace Stellaegis.Issuer.Tests;

/// <summary>A resource server apart from the issuer: what it accepts, what it refuses, how it learns of a revocation.</summary>
public sealed class ResourceServerTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task A_resource_server_accepts_a_token_of_the_issuer_and_reads_its_subject_and_scopes()
    {
        await using var issuer = await IssuerTestHost.Builder().StartAsync(Ct);
        await issuer.DeclarePublicClientAsync(ct: Ct);
        var (code, verifier) = await issuer.AuthorizeAsync("jane", ct: Ct);
        var tokens = await issuer.ExchangeCodeAsync(code, verifier, ct: Ct);
        await using var resource = await ResourceServerTestHost.StartAsync(issuer, Ct);

        var response = await resource.ClientWithBearer(tokens.AccessToken).GetAsync("/ping", Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var pong = (await response.Content.ReadFromJsonAsync<Pong>(Ct))!;
        Assert.Equal("jane", pong.Subject);
        Assert.Contains("documents", pong.Scopes);                                 // one claim per scope
        Assert.Contains("openid", pong.Scopes);
        Assert.Equal(HttpStatusCode.Unauthorized, (await resource.GetTestClient().GetAsync("/ping", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await resource.ClientWithBearer("not.a.token").GetAsync("/ping", Ct)).StatusCode);
    }

    [Fact]
    public async Task A_token_for_another_audience_is_refused()
    {
        await using var issuer = await IssuerTestHost.Builder().StartAsync(Ct);
        await issuer.DeclarePublicClientAsync(ct: Ct);
        var (code, verifier) = await issuer.AuthorizeAsync("jane", ct: Ct);
        var tokens = await issuer.ExchangeCodeAsync(code, verifier, ct: Ct);
        await using var rendering = await ResourceServerTestHost.StartAsync(issuer, Ct, audiences: ["rendering"]);

        Assert.Equal(HttpStatusCode.Unauthorized, (await rendering.ClientWithBearer(tokens.AccessToken).GetAsync("/ping", Ct)).StatusCode);
    }

    [Fact]
    public async Task A_revoked_token_is_refused_once_the_resource_server_read_the_issuer_and_at_once_when_the_host_is_told()
    {
        await using var issuer = await IssuerTestHost.Builder().StartAsync(Ct);
        await issuer.DeclarePublicClientAsync(ct: Ct);
        var (code, verifier) = await issuer.AuthorizeAsync("jane", ct: Ct);
        var tokens = await issuer.ExchangeCodeAsync(code, verifier, ct: Ct);
        var tokenId = IssuerTestHost.Payload(tokens.AccessToken).GetProperty(RevokedTokens.TokenIdClaim).GetString()!;
        await using var resource = await ResourceServerTestHost.StartAsync(issuer, Ct);
        var client = resource.ClientWithBearer(tokens.AccessToken);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/ping", Ct)).StatusCode);

        using (var scope = issuer.Services.CreateScope())
            Assert.True((await scope.ServiceProvider.GetRequiredService<ITokenRevoker>().RevokeTokenAsync(tokenId, Ct)).IsSuccess);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/ping", Ct)).StatusCode);      // the resource server does not know yet

        await resource.ReconcileAsync(Ct);                                                   // the reading of the issuer's route
        var refused = await client.GetAsync("/ping", Ct);
        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
        Assert.Equal(IssuerClientErrors.TokenRevokedCode, await refused.CodeOfAsync(Ct));

        // Another token, revoked at the issuer and told to the host by its bus: refused without a reading.
        var (code2, verifier2) = await issuer.AuthorizeAsync("jane", ct: Ct);
        var second = await issuer.ExchangeCodeAsync(code2, verifier2, ct: Ct);
        var client2 = resource.ClientWithBearer(second.AccessToken);
        Assert.Equal(HttpStatusCode.OK, (await client2.GetAsync("/ping", Ct)).StatusCode);
        var announced = issuer.Events().Events.OfType<TokenRevokedEvent>().ToList();
        using (var scope = issuer.Services.CreateScope())
            await scope.ServiceProvider.GetRequiredService<ITokenRevoker>().RevokeSubjectAsync("jane", Ct);
        var told = issuer.Events().Events.OfType<TokenRevokedEvent>().Skip(announced.Count).Single();
        resource.RevokedTokens().Revoke(told.TokenId, told.ExpiresAt);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client2.GetAsync("/ping", Ct)).StatusCode);
    }

    [Fact]
    public async Task The_periodic_reading_catches_a_revocation_no_event_told()
    {
        await using var issuer = await IssuerTestHost.Builder().StartAsync(Ct);
        await issuer.DeclarePublicClientAsync(ct: Ct);
        var (code, verifier) = await issuer.AuthorizeAsync("jane", ct: Ct);
        var tokens = await issuer.ExchangeCodeAsync(code, verifier, ct: Ct);
        var tokenId = IssuerTestHost.Payload(tokens.AccessToken).GetProperty(RevokedTokens.TokenIdClaim).GetString()!;
        await using var resource = await ResourceServerTestHost.StartAsync(issuer, Ct, reconcileInterval: TimeSpan.FromMilliseconds(50));
        var client = resource.ClientWithBearer(tokens.AccessToken);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/ping", Ct)).StatusCode);

        using (var scope = issuer.Services.CreateScope())
            await scope.ServiceProvider.GetRequiredService<ITokenRevoker>().RevokeTokenAsync(tokenId, Ct);

        var status = HttpStatusCode.OK;
        for (var attempt = 0; attempt < 100 && status == HttpStatusCode.OK; attempt++)
        {
            await Task.Delay(50, Ct);
            status = (await client.GetAsync("/ping", Ct)).StatusCode;
        }
        Assert.Equal(HttpStatusCode.Unauthorized, status);
    }

    [Fact]
    public async Task An_encrypted_token_is_read_by_the_resource_server_that_holds_the_key_and_by_no_other()
    {
        await using var issuer = await IssuerTestHost.Builder(options => options.EncryptAccessTokens = true).StartAsync(Ct);
        await issuer.DeclarePublicClientAsync(ct: Ct);
        var (code, verifier) = await issuer.AuthorizeAsync("jane", ct: Ct);
        var tokens = await issuer.ExchangeCodeAsync(code, verifier, ct: Ct);
        Assert.Equal(5, tokens.AccessToken.Split('.').Length);                                // a JWE, not a JWS
        var key = issuer.Services.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue.EncryptionCredentials[0].Key;

        await using var holding = await ResourceServerTestHost.StartAsync(issuer, Ct, decryptionKey: key);
        var accepted = await holding.ClientWithBearer(tokens.AccessToken).GetAsync("/ping", Ct);
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        Assert.Equal("jane", (await accepted.Content.ReadFromJsonAsync<Pong>(Ct))!.Subject);

        await using var without = await ResourceServerTestHost.StartAsync(issuer, Ct);
        Assert.Equal(HttpStatusCode.Unauthorized, (await without.ClientWithBearer(tokens.AccessToken).GetAsync("/ping", Ct)).StatusCode);
    }

    [Fact]
    public async Task The_http_source_reads_the_revoked_tokens_of_the_issuer_with_its_token_and_says_so_without()
    {
        await using var issuer = await IssuerTestHost.Builder().StartAsync(Ct);
        await issuer.DeclarePublicClientAsync(ct: Ct);
        var (code, verifier) = await issuer.AuthorizeAsync("jane", ct: Ct);
        var tokens = await issuer.ExchangeCodeAsync(code, verifier, ct: Ct);
        var tokenId = IssuerTestHost.Payload(tokens.AccessToken).GetProperty(RevokedTokens.TokenIdClaim).GetString()!;
        using (var scope = issuer.Services.CreateScope())
            await scope.ServiceProvider.GetRequiredService<ITokenRevoker>().RevokeTokenAsync(tokenId, Ct);

        await using var resource = await ResourceServerTestHost.StartAsync(issuer, Ct);
        using var scoped = resource.Services.CreateScope();
        var listed = await scoped.ServiceProvider.GetRequiredService<IRevokedTokensSource>().GetRevokedTokensAsync(Ct);
        Assert.Equal(tokenId, Assert.Single(listed).TokenId);

        await using var anonymous = await ResourceServerTestHost.StartAsync(issuer, Ct, issuerClientToken: null);   // the reading at startup failed, logged; the host serves
        using var scopedAnonymous = anonymous.Services.CreateScope();
        var exception = await Assert.ThrowsAsync<HttpRequestException>(() => scopedAnonymous.ServiceProvider.GetRequiredService<IRevokedTokensSource>().GetRevokedTokensAsync(Ct));
        Assert.Equal(HttpStatusCode.Unauthorized, exception.StatusCode);
    }

    [Fact]
    public async Task An_admission_without_a_source_of_the_revoked_tokens_fails_the_startup()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddStellaegisIssuerAdmission();
        var app = builder.Build();

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => app.StartAsync(Ct));

        Assert.Contains("AddStellaegisIssuerClient", exception.Message);
    }

    [Fact]
    public void The_options_of_a_resource_server_take_the_form_of_the_family()
    {
        Assert.Equal("Stellaegis:Issuer:Bearer", IssuerBearerOptions.SectionName);
        Assert.Contains("Authority", new IssuerBearerOptions().FindError());
        Assert.Contains("Audiences", new IssuerBearerOptions { Authority = "https://id.acme.test" }.FindError());
        Assert.Null(new IssuerBearerOptions { Authority = "https://id.acme.test", Audiences = ["documents"] }.FindError());
        Assert.Contains("Decryption", new IssuerBearerOptions { Authority = "https://id.acme.test", Audiences = ["documents"], Decryption = new IssuerCertificateOptions { Path = "a.pfx", Thumbprint = "b" } }.FindError());
        Assert.Equal("Stellaegis:Issuer:Client", IssuerClientOptions.SectionName);
        Assert.Contains("BaseUrl", new IssuerClientOptions().FindError());
        Assert.Equal("Stellaegis:Issuer:Admission", IssuerAdmissionOptions.SectionName);
        Assert.Contains("ReconcileInterval", new IssuerAdmissionOptions { ReconcileInterval = TimeSpan.FromSeconds(-1) }.FindError());
        Assert.Throws<InvalidOperationException>(() => new ServiceCollection().AddStellaegisBearer(options => options.Authority = "not a url"));
    }
}
