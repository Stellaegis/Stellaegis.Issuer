using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;

namespace Stellaegis.Issuer.Tests;

/// <summary>The three flows, on the test server: a person through the host's authentication, a service through its secret.</summary>
public sealed class FlowTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task A_native_client_comes_back_on_any_loopback_port_and_a_browser_client_on_its_exact_address()
    {
        await using var app = await IssuerTestHost.Builder().StartAsync(Ct);
        await app.DeclarePublicClientAsync("desktop", kind: ClientKind.Native, redirectUri: "http://127.0.0.1/callback", ct: Ct);
        await app.DeclarePublicClientAsync("browser", redirectUri: "http://127.0.0.1/callback", ct: Ct);
        var (_, challenge) = IssuerTestHost.Pkce();
        using var jane = app.ClientAs("jane");

        // The native application listens on whatever port was free: the issuer ignores it (RFC 8252 § 7.3).
        var native = await jane.GetAsync(IssuerTestHost.AuthorizeUrl("desktop", challenge, redirectUri: "http://127.0.0.1:54321/callback"), Ct);
        Assert.Equal(HttpStatusCode.Redirect, native.StatusCode);
        Assert.StartsWith("http://127.0.0.1:54321/callback?code=", native.Headers.Location!.ToString());

        // A browser application is sent back to its exact address only.
        var browser = await jane.GetAsync(IssuerTestHost.AuthorizeUrl("browser", challenge, redirectUri: "http://127.0.0.1:54321/callback"), Ct);
        Assert.Equal(HttpStatusCode.BadRequest, browser.StatusCode);

        using var services = app.Services.CreateScope();
        var client = await services.ServiceProvider.GetRequiredService<IssuerCatalog>().GetClientAsync("desktop", Ct);
        Assert.Equal(ClientKind.Native, client.Value.Kind);
    }

    [Fact]
    public async Task A_public_client_gets_its_tokens_by_code_and_PKCE_and_refreshes_them()
    {
        await using var app = await IssuerTestHost.Builder().StartAsync(Ct);
        await app.DeclarePublicClientAsync(ct: Ct);

        var (code, verifier) = await app.AuthorizeAsync("jane", ct: Ct);
        var tokens = await app.ExchangeCodeAsync(code, verifier, ct: Ct);

        Assert.Equal(HttpStatusCode.OK, tokens.Status);
        Assert.NotEmpty(tokens.AccessToken);
        Assert.NotEmpty(tokens.RefreshToken);
        Assert.NotEmpty(tokens.IdToken);
        var access = IssuerTestHost.Payload(tokens.AccessToken);
        Assert.Equal("jane", access.GetProperty("sub").GetString());
        Assert.Equal("jane@acme.test", access.GetProperty("email").GetString());
        Assert.Equal("documents", Audiences(access).Single());
        Assert.False(access.TryGetProperty("name", out _));           // the name goes to the identity token only
        Assert.NotEmpty(access.GetProperty("oi_tkn_id").GetString()!);
        var id = IssuerTestHost.Payload(tokens.IdToken);
        Assert.Equal("jane", id.GetProperty("name").GetString());

        var refreshed = await app.RefreshAsync(tokens.RefreshToken, ct: Ct);
        Assert.Equal(HttpStatusCode.OK, refreshed.Status);
        Assert.NotEqual(tokens.AccessToken, refreshed.AccessToken);
        Assert.Equal("jane", IssuerTestHost.Payload(refreshed.AccessToken).GetProperty("sub").GetString());
    }

    [Fact]
    public async Task A_code_without_its_verifier_is_refused()
    {
        await using var app = await IssuerTestHost.Builder().StartAsync(Ct);
        await app.DeclarePublicClientAsync(ct: Ct);
        var (code, _) = await app.AuthorizeAsync("jane", ct: Ct);

        var tokens = await app.ExchangeCodeAsync(code, "not-the-verifier", ct: Ct);

        Assert.Equal(HttpStatusCode.BadRequest, tokens.Status);
        Assert.Equal("invalid_grant", tokens.Error);
    }

    [Fact]
    public async Task A_confidential_client_gets_a_token_by_its_credentials_with_the_module_as_audience()
    {
        await using var app = await IssuerTestHost.Builder().StartAsync(Ct);
        ProvisionedClient documents;
        using (var scope = app.Services.CreateScope())
        {
            var provisioned = await scope.ServiceProvider.GetRequiredService<IOidcClientProvisioner>().ProvisionModuleClientAsync("documents", Ct);
            Assert.True(provisioned.IsSuccess, provisioned.Error?.ToString());
            documents = provisioned.Value;
        }

        var tokens = await app.ClientCredentialsAsync(documents.ClientId, documents.Secret, "documents", Ct);

        Assert.Equal(HttpStatusCode.OK, tokens.Status);
        var access = IssuerTestHost.Payload(tokens.AccessToken);
        Assert.Equal("documents", access.GetProperty("sub").GetString());
        Assert.Equal("documents", access.GetProperty("client_id").GetString());
        Assert.Equal("documents", Audiences(access).Single());
        Assert.Empty(tokens.RefreshToken);
        Assert.Empty(tokens.IdToken);

        var wrong = await app.ClientCredentialsAsync(documents.ClientId, "wrong", "documents", Ct);
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.Status);
        Assert.Equal("invalid_client", wrong.Error);
    }

    [Fact]
    public async Task A_person_nobody_authenticated_is_challenged_on_the_hosts_scheme()
    {
        await using var app = await IssuerTestHost.Builder().StartAsync(Ct);
        await app.DeclarePublicClientAsync(ct: Ct);
        var (_, challenge) = IssuerTestHost.Pkce();

        using var anonymous = app.ClientAs(null);
        var response = await anonymous.GetAsync(IssuerTestHost.AuthorizeUrl("desktop", challenge), Ct);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);   // what the header scheme answers a challenge; a cookie would redirect to /login
    }

    [Fact]
    public async Task A_subject_the_host_no_longer_admits_is_refused_at_the_authorization_and_at_the_refresh()
    {
        await using var app = await IssuerTestHost.Builder().StartAsync(Ct);
        await app.DeclarePublicClientAsync(ct: Ct);
        var (code, verifier) = await app.AuthorizeAsync("jane", ct: Ct);
        var tokens = await app.ExchangeCodeAsync(code, verifier, ct: Ct);
        Assert.Equal(HttpStatusCode.OK, tokens.Status);

        app.Refusing().Refused.Add("jane");

        var refreshed = await app.RefreshAsync(tokens.RefreshToken, ct: Ct);
        Assert.Equal(HttpStatusCode.BadRequest, refreshed.Status);
        Assert.Equal("invalid_grant", refreshed.Error);
        Assert.Equal("The account is blocked.", refreshed.ErrorDescription);

        var signOuts = HeaderAuthentication.SignOuts;
        var (_, challenge) = IssuerTestHost.Pkce();
        using var jane = app.ClientAs("jane");
        var response = await jane.GetAsync(IssuerTestHost.AuthorizeUrl("desktop", challenge), Ct);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var query = QueryHelpers.ParseQuery(response.Headers.Location!.Query);
        Assert.Equal("access_denied", query["error"].ToString());
        Assert.Equal("The account is blocked.", query["error_description"].ToString());
        Assert.Equal(signOuts + 1, HeaderAuthentication.SignOuts);       // the person is signed out of the host's scheme
    }

    [Fact]
    public async Task An_unknown_scope_and_an_unknown_client_are_refused()
    {
        await using var app = await IssuerTestHost.Builder().StartAsync(Ct);
        await app.DeclarePublicClientAsync(ct: Ct);
        var (_, challenge) = IssuerTestHost.Pkce();

        using var jane = app.ClientAs("jane");
        var unknownScope = await jane.GetAsync(IssuerTestHost.AuthorizeUrl("desktop", challenge, scope: "openid nowhere"), Ct);
        var unknownClient = await jane.GetAsync(IssuerTestHost.AuthorizeUrl("nobody", challenge), Ct);

        Assert.Equal(HttpStatusCode.BadRequest, unknownScope.StatusCode);   // OpenIddict answers in place: the request did not hold
        Assert.Contains("invalid_scope", await unknownScope.Content.ReadAsStringAsync(Ct));
        Assert.Equal(HttpStatusCode.BadRequest, unknownClient.StatusCode);
        Assert.Contains("invalid_request", await unknownClient.Content.ReadAsStringAsync(Ct));   // the client identifier is invalid
    }

    private static IEnumerable<string> Audiences(JsonElement payload)
    {
        var aud = payload.GetProperty("aud");
        return aud.ValueKind == JsonValueKind.Array ? aud.EnumerateArray().Select(a => a.GetString()!) : [aud.GetString()!];
    }
}
