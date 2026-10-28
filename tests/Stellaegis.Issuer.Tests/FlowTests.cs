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
        Assert.Equal("jane", access.GetProperty("name").GetString());   // the user information answers from this token
        Assert.NotEmpty(access.GetProperty("oi_tkn_id").GetString()!);
        var id = IssuerTestHost.Payload(tokens.IdToken);
        Assert.Equal("jane", id.GetProperty("name").GetString());

        var refreshed = await app.RefreshAsync(tokens.RefreshToken, ct: Ct);
        Assert.Equal(HttpStatusCode.OK, refreshed.Status);
        Assert.NotEqual(tokens.AccessToken, refreshed.AccessToken);
        Assert.Equal("jane", IssuerTestHost.Payload(refreshed.AccessToken).GetProperty("sub").GetString());
    }

    [Fact]
    public async Task How_the_person_proved_who_they_are_goes_into_both_tokens_and_survives_the_refresh()
    {
        await using var app = await IssuerTestHost.Builder().StartAsync(Ct);
        await app.DeclarePublicClientAsync(ct: Ct);

        var (code, verifier) = await app.AuthorizeAsync("jane", ct: Ct, amr: "pwd otp mfa");
        var tokens = await app.ExchangeCodeAsync(code, verifier, ct: Ct);

        string[] Methods(string jwt) => IssuerTestHost.Payload(jwt).GetProperty("amr").EnumerateArray().Select(value => value.GetString()!).Order().ToArray();
        Assert.Equal(["mfa", "otp", "pwd"], Methods(tokens.AccessToken));
        Assert.Equal(["mfa", "otp", "pwd"], Methods(tokens.IdToken));
        var refreshed = await app.RefreshAsync(tokens.RefreshToken, ct: Ct);
        Assert.Equal(["mfa", "otp", "pwd"], Methods(refreshed.AccessToken));   // those of the login, not of the refresh

        // A single method is still an array (OpenID Connect Core § 2), and a session that says none gives none.
        (code, verifier) = await app.AuthorizeAsync("john", ct: Ct, amr: "pwd");
        Assert.Equal(["pwd"], Methods((await app.ExchangeCodeAsync(code, verifier, ct: Ct)).AccessToken));
        (code, verifier) = await app.AuthorizeAsync("joe", ct: Ct);
        Assert.False(IssuerTestHost.Payload((await app.ExchangeCodeAsync(code, verifier, ct: Ct)).AccessToken).TryGetProperty("amr", out _));
    }

    private static readonly Dictionary<string, string> Profile = new()
    {
        ["locale"] = "fr",
        ["zoneinfo"] = "Europe/Paris",
        ["picture"] = "https://id.acme.test/account/avatar?v=1",
    };

    [Fact]
    public async Task The_profile_of_the_session_goes_into_both_tokens_and_survives_the_refresh()
    {
        await using var app = await IssuerTestHost.Builder().StartAsync(Ct);
        await app.DeclarePublicClientAsync(ct: Ct);

        var (code, verifier) = await app.AuthorizeAsync("jane", ct: Ct, profile: Profile);
        var tokens = await app.ExchangeCodeAsync(code, verifier, ct: Ct);

        foreach (var jwt in new[] { tokens.AccessToken, tokens.IdToken })
        {
            var payload = IssuerTestHost.Payload(jwt);
            Assert.Equal("fr", payload.GetProperty("locale").GetString());
            Assert.Equal("Europe/Paris", payload.GetProperty("zoneinfo").GetString());
            Assert.Equal("https://id.acme.test/account/avatar?v=1", payload.GetProperty("picture").GetString());
            Assert.Equal("jane", payload.GetProperty("name").GetString());
        }
        var refreshed = await app.RefreshAsync(tokens.RefreshToken, ct: Ct);
        Assert.Equal("Europe/Paris", IssuerTestHost.Payload(refreshed.AccessToken).GetProperty("zoneinfo").GetString());

        // A session that carries no profile gives none.
        (code, verifier) = await app.AuthorizeAsync("john", ct: Ct);
        var plain = IssuerTestHost.Payload((await app.ExchangeCodeAsync(code, verifier, ct: Ct)).AccessToken);
        Assert.False(plain.TryGetProperty("locale", out _));
        Assert.False(plain.TryGetProperty("picture", out _));
    }

    [Fact]
    public async Task The_user_information_answers_the_claims_of_the_access_token_under_their_scopes()
    {
        await using var app = await IssuerTestHost.Builder().StartAsync(Ct);
        await app.DeclarePublicClientAsync(ct: Ct);
        using var anonymous = app.GetTestClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync(IssuerEndpoints.UserInfoPath, Ct)).StatusCode);

        var (code, verifier) = await app.AuthorizeAsync("jane", ct: Ct, profile: Profile);
        var full = await UserInfoAsync(app, (await app.ExchangeCodeAsync(code, verifier, ct: Ct)).AccessToken);
        Assert.Equal("jane", full.GetProperty("sub").GetString());
        Assert.Equal("jane@acme.test", full.GetProperty("email").GetString());
        Assert.Equal("jane", full.GetProperty("name").GetString());
        Assert.Equal("fr", full.GetProperty("locale").GetString());
        Assert.Equal("Europe/Paris", full.GetProperty("zoneinfo").GetString());
        Assert.Equal("https://id.acme.test/account/avatar?v=1", full.GetProperty("picture").GetString());

        (code, verifier) = await app.AuthorizeAsync("jane", ct: Ct, profile: Profile, scope: "openid documents");
        var bare = await UserInfoAsync(app, (await app.ExchangeCodeAsync(code, verifier, ct: Ct)).AccessToken);
        Assert.Equal("jane", bare.GetProperty("sub").GetString());
        Assert.False(bare.TryGetProperty("email", out _));
        Assert.False(bare.TryGetProperty("name", out _));
        Assert.False(bare.TryGetProperty("locale", out _));
    }

    private static async Task<System.Text.Json.JsonElement> UserInfoAsync(Microsoft.AspNetCore.Builder.WebApplication app, string accessToken)
    {
        using var client = app.GetTestClient();
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
        var response = await client.GetAsync(IssuerEndpoints.UserInfoPath, Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return System.Text.Json.JsonDocument.Parse(await response.Content.ReadAsStringAsync(Ct)).RootElement;
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

        var signOuts = app.SignOuts();
        var (_, challenge) = IssuerTestHost.Pkce();
        using var jane = app.ClientAs("jane");
        var response = await jane.GetAsync(IssuerTestHost.AuthorizeUrl("desktop", challenge), Ct);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var query = QueryHelpers.ParseQuery(response.Headers.Location!.Query);
        Assert.Equal("access_denied", query["error"].ToString());
        Assert.Equal("The account is blocked.", query["error_description"].ToString());
        Assert.Equal(signOuts + 1, app.SignOuts());       // the person is signed out of the host's scheme
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

    [Fact]
    public async Task The_time_of_the_login_goes_into_both_tokens_as_a_number_and_survives_the_refresh()
    {
        await using var app = await IssuerTestHost.Builder().StartAsync(Ct);
        await app.DeclarePublicClientAsync(ct: Ct);
        var signedInAt = DateTimeOffset.UtcNow.AddMinutes(-20).ToUnixTimeSeconds();

        var (code, verifier) = await app.AuthorizeAsync("jane", ct: Ct, profile: new Dictionary<string, string> { ["auth_time"] = signedInAt.ToString() });
        var tokens = await app.ExchangeCodeAsync(code, verifier, ct: Ct);

        Assert.Equal(signedInAt, IssuerTestHost.Payload(tokens.AccessToken).GetProperty("auth_time").GetInt64());
        Assert.Equal(signedInAt, IssuerTestHost.Payload(tokens.IdToken).GetProperty("auth_time").GetInt64());
        var refreshed = await app.RefreshAsync(tokens.RefreshToken, ct: Ct);
        Assert.Equal(signedInAt, IssuerTestHost.Payload(refreshed.AccessToken).GetProperty("auth_time").GetInt64());   // the login's, not the refresh's

        (code, verifier) = await app.AuthorizeAsync("john", ct: Ct);
        Assert.False(IssuerTestHost.Payload((await app.ExchangeCodeAsync(code, verifier, ct: Ct)).AccessToken).TryGetProperty("auth_time", out _));
    }

    [Fact]
    public async Task Prompt_login_closes_the_open_session_and_sends_the_person_to_sign_in_on_a_way_back_that_no_longer_asks_it()
    {
        await using var app = await IssuerTestHost.Builder().StartAsync(Ct);
        await app.DeclarePublicClientAsync(ct: Ct);
        var (_, challenge) = IssuerTestHost.Pkce();
        var authorize = IssuerTestHost.AuthorizeUrl("desktop", challenge);
        using var jane = app.ClientAs("jane");

        var signOuts = app.SignOuts();
        var asked = await jane.GetAsync(QueryHelpers.AddQueryString(authorize, "prompt", "login"), Ct);

        Assert.Equal(HttpStatusCode.Unauthorized, asked.StatusCode);
        Assert.Equal(signOuts + 1, app.SignOuts());
        Assert.Equal(authorize, asked.Headers.GetValues("X-Return").Single());

        // Back from the login, the way back no longer asks it: the code is given.
        var back = await jane.GetAsync(authorize, Ct);
        Assert.Equal(HttpStatusCode.Redirect, back.StatusCode);
        Assert.True(QueryHelpers.ParseQuery(back.Headers.Location!.Query).ContainsKey("code"));
    }

    [Fact]
    public async Task Max_age_is_answered_by_a_recent_login_and_asks_again_one_older_or_one_that_does_not_say_its_time()
    {
        await using var app = await IssuerTestHost.Builder().StartAsync(Ct);
        await app.DeclarePublicClientAsync(ct: Ct);
        var (_, challenge) = IssuerTestHost.Pkce();
        var authorize = IssuerTestHost.AuthorizeUrl("desktop", challenge);
        var asking = QueryHelpers.AddQueryString(authorize, "max_age", "600");

        HttpClient Session(long? minutesAgo) => app.ClientAs("jane", profile: minutesAgo is { } ago
            ? new Dictionary<string, string> { ["auth_time"] = DateTimeOffset.UtcNow.AddMinutes(-ago).ToUnixTimeSeconds().ToString() }
            : null);

        using (var recent = Session(2))
        {
            var answered = await recent.GetAsync(asking, Ct);
            Assert.Equal(HttpStatusCode.Redirect, answered.StatusCode);
            Assert.True(QueryHelpers.ParseQuery(answered.Headers.Location!.Query).ContainsKey("code"));
        }
        foreach (var minutesAgo in new long?[] { 30, null })
        {
            using var session = Session(minutesAgo);
            var signOuts = app.SignOuts();
            var asked = await session.GetAsync(asking, Ct);
            Assert.Equal(HttpStatusCode.Unauthorized, asked.StatusCode);
            Assert.Equal(signOuts + 1, app.SignOuts());
            Assert.Equal(authorize, asked.Headers.GetValues("X-Return").Single());
        }
    }

    [Fact]
    public async Task Prompt_none_answers_an_open_session_and_says_login_required_rather_than_showing_the_login()
    {
        await using var app = await IssuerTestHost.Builder().StartAsync(Ct);
        await app.DeclarePublicClientAsync(ct: Ct);
        var (_, challenge) = IssuerTestHost.Pkce();
        var silent = QueryHelpers.AddQueryString(IssuerTestHost.AuthorizeUrl("desktop", challenge), "prompt", "none");

        string? ErrorOf(HttpResponseMessage response)
        {
            Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
            Assert.StartsWith(IssuerTestHost.RedirectUri, response.Headers.Location!.ToString());
            var query = QueryHelpers.ParseQuery(response.Headers.Location.Query);
            return query.TryGetValue("error", out var error) ? error.ToString() : null;
        }

        using (var anonymous = app.ClientAs(null))
            Assert.Equal("login_required", ErrorOf(await anonymous.GetAsync(silent, Ct)));
        using (var jane = app.ClientAs("jane"))
            Assert.Null(ErrorOf(await jane.GetAsync(silent, Ct)));

        // A login max_age would ask again is not asked: the session stays open, the application is told.
        using var older = app.ClientAs("jane", profile: new Dictionary<string, string> { ["auth_time"] = DateTimeOffset.UtcNow.AddHours(-2).ToUnixTimeSeconds().ToString() });
        var signOuts = app.SignOuts();
        Assert.Equal("login_required", ErrorOf(await older.GetAsync(QueryHelpers.AddQueryString(silent, "max_age", "600"), Ct)));
        Assert.Equal(signOuts, app.SignOuts());
    }

    [Fact]
    public async Task Prompt_select_account_sends_the_open_session_to_the_login_page_without_closing_it()
    {
        await using var app = await IssuerTestHost.Builder().StartAsync(Ct);
        await app.DeclarePublicClientAsync(ct: Ct);
        var (_, challenge) = IssuerTestHost.Pkce();
        var authorize = IssuerTestHost.AuthorizeUrl("desktop", challenge);
        using var jane = app.ClientAs("jane");

        var signOuts = app.SignOuts();
        var asked = await jane.GetAsync(QueryHelpers.AddQueryString(authorize, "prompt", "select_account"), Ct);

        Assert.Equal(HttpStatusCode.Unauthorized, asked.StatusCode);
        Assert.Equal(authorize, asked.Headers.GetValues("X-Return").Single());
        Assert.Equal(signOuts, app.SignOuts());

        // "Continue" on the login page comes back on the way back, which no longer asks: the code is given.
        var continued = await jane.GetAsync(authorize, Ct);
        Assert.Equal(HttpStatusCode.Redirect, continued.StatusCode);
        Assert.True(QueryHelpers.ParseQuery(continued.Headers.Location!.Query).ContainsKey("code"));
    }
}
