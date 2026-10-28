using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Stellaegis.Issuer.Server;
using Stellaegis.Issuer.Tests.HostPages;

namespace Stellaegis.Issuer.Tests;

/// <summary>The sessions page: what a person sees of the applications signed in on their behalf, and ends.</summary>
public sealed class SessionsPageTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static readonly Regex AuthorizationIdPattern = new("name=\"authorizationId\" value=\"([^\"]+)\"", RegexOptions.Compiled);

    private static async Task<WebApplication> StartAsync(Action<IssuerPagesOptions>? pages = null, bool hostLayout = false)
    {
        var builder = IssuerTestHost.Builder();
        if (hostLayout)
            builder.Services.AddRazorPages().AddApplicationPart(typeof(HostPages.HostPages).Assembly);
        builder.Services.AddStellaegisIssuerPages(options =>
        {
            options.ApplicationName = "Acme";
            options.Culture = "en";
            pages?.Invoke(options);
        });
        var app = await builder.StartAsync(Ct, map: app => app.MapStellaegisIssuerPages());
        await app.DeclarePublicClientAsync(ct: Ct);
        return app;
    }

    private static async Task<TokenResponse> SignInAsync(WebApplication app, string subject)
    {
        var (code, verifier) = await app.AuthorizeAsync(subject, ct: Ct);
        return await app.ExchangeCodeAsync(code, verifier, ct: Ct);
    }

    [Fact]
    public async Task The_page_lists_the_sessions_of_the_person_and_ends_one()
    {
        await using var app = await StartAsync();
        var tokens = await SignInAsync(app, "jane");
        var kept = await SignInAsync(app, "jane");
        await SignInAsync(app, "john");
        var browser = new Browser(app, "jane");

        var page = await browser.GetAsync("/account/sessions", Ct);
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        Assert.Contains("__RequestVerificationToken", browser.Html);
        Assert.Contains("stellaegis-issuer", browser.Html);                                    // the package's own layout, no account layout here
        Assert.Contains("Acme", browser.Html);
        Assert.Contains("desktop", browser.Html);                                              // the client signed in
        Assert.Contains("active token", browser.Html);
        Assert.Contains("/_content/Stellaegis.Issuer.Server/issuer.css", browser.Html);
        var sessions = AuthorizationIdPattern.Matches(browser.Html);
        Assert.Equal(2, sessions.Count);                                                       // jane's two, not john's

        var ended = await browser.PostFormAsync("/account/sessions", new Dictionary<string, string> { ["authorizationId"] = sessions[1].Groups[1].Value }, Ct, postPath: "/account/sessions?handler=Revoke");
        Assert.Equal(HttpStatusCode.Redirect, ended.StatusCode);
        Assert.Equal("/account/sessions", ended.Headers.Location!.ToString());
        await browser.GetAsync("/account/sessions", Ct);
        Assert.Contains("The session was ended.", browser.Html);
        Assert.Single(AuthorizationIdPattern.Matches(browser.Html));
        var first = await app.RefreshAsync(tokens.RefreshToken, ct: Ct);
        var second = await app.RefreshAsync(kept.RefreshToken, ct: Ct);
        Assert.True(first.Error == "invalid_grant" ^ second.Error == "invalid_grant");          // one session ended, the other kept

        // John's session is not Jane's to end.
        var johns = new Browser(app, "john");
        await johns.GetAsync("/account/sessions", Ct);
        var johnsSession = AuthorizationIdPattern.Match(johns.Html).Groups[1].Value;
        var refused = await browser.PostFormAsync("/account/sessions", new Dictionary<string, string> { ["authorizationId"] = johnsSession }, Ct, postPath: "/account/sessions?handler=Revoke");
        Assert.Equal(HttpStatusCode.Redirect, refused.StatusCode);
        await browser.GetAsync("/account/sessions", Ct);
        Assert.Contains("This session is not yours.", browser.Html);
        await johns.GetAsync("/account/sessions", Ct);
        Assert.Single(AuthorizationIdPattern.Matches(johns.Html));
    }

    [Fact]
    public async Task Ending_every_session_signs_the_person_out_of_the_host_and_sends_them_away()
    {
        await using var app = await StartAsync(options => options.AfterRevokeAllPath = "/bye");
        var tokens = await SignInAsync(app, "jane");
        var browser = new Browser(app, "jane");
        var signOuts = app.SignOuts();

        var away = await browser.PostFormAsync("/account/sessions", new Dictionary<string, string>(), Ct, postPath: "/account/sessions?handler=RevokeAll");

        Assert.Equal(HttpStatusCode.Redirect, away.StatusCode);
        Assert.Equal("/bye", away.Headers.Location!.ToString());
        Assert.Equal(signOuts + 1, app.SignOuts());
        Assert.Equal("invalid_grant", (await app.RefreshAsync(tokens.RefreshToken, ct: Ct)).Error);
        Assert.Single(app.Events().Events.OfType<TokenRevokedEvent>());
    }

    [Fact]
    public async Task The_page_renders_inside_the_account_layout_of_the_host_when_it_has_one()
    {
        await using var app = await StartAsync(hostLayout: true);
        await SignInAsync(app, "jane");
        var browser = new Browser(app, "jane");

        await browser.GetAsync("/account/sessions", Ct);

        Assert.Contains(HostPages.HostPages.LayoutMarker, browser.Html);
        Assert.DoesNotContain("stellaegis-issuer", browser.Html);
        Assert.Contains("desktop", browser.Html);
    }

    [Fact]
    public async Task The_page_speaks_the_language_of_the_options_and_refuses_an_anonymous_person()
    {
        await using var app = await StartAsync(options => options.Culture = "fr");
        var browser = new Browser(app, "jane");

        await browser.GetAsync("/account/sessions", Ct);
        Assert.Contains("en votre nom", browser.Html);                                           // the accents are encoded by Razor
        Assert.Contains("lang=\"fr\"", browser.Html);

        Assert.Equal(HttpStatusCode.Unauthorized, (await app.GetTestClient().GetAsync("/account/sessions", Ct)).StatusCode);
    }

    [Fact]
    public void The_options_take_the_form_of_the_family()
    {
        Assert.Equal("Stellaegis:Issuer:Pages", IssuerPagesOptions.SectionName);
        Assert.Null(new IssuerPagesOptions().FindError());
        Assert.Contains("ApplicationName", new IssuerPagesOptions { ApplicationName = " " }.FindError());
        Assert.Contains("Culture", new IssuerPagesOptions { Culture = "xx-NOWHERE" }.FindError());
        Assert.Contains("AfterRevokeAllPath", new IssuerPagesOptions { AfterRevokeAllPath = "https://elsewhere" }.FindError());
    }
}

/// <summary>
/// A browser of the test server, signed in as one person by the header authentication: keeps the cookies the
/// pages set, reads the antiforgery token of a page, posts a form. Redirects are not followed.
/// </summary>
internal sealed class Browser(WebApplication app, string subject)
{
    private static readonly Regex TokenPattern = new("name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"", RegexOptions.Compiled);

    private readonly HttpClient _client = app.ClientAs(subject);
    private readonly Dictionary<string, string> _cookies = new(StringComparer.Ordinal);

    public string Html { get; private set; } = "";

    public async Task<HttpResponseMessage> GetAsync(string path, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        return await SendAsync(request, ct);
    }

    public async Task<HttpResponseMessage> PostFormAsync(string path, IDictionary<string, string> fields, CancellationToken ct, string? postPath = null)
    {
        var page = await GetAsync(path, ct);
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        var token = TokenPattern.Match(Html).Groups[1].Value;
        Assert.False(string.IsNullOrEmpty(token), "The page carries no antiforgery token.");
        var form = new Dictionary<string, string>(fields) { ["__RequestVerificationToken"] = token };
        using var request = new HttpRequestMessage(HttpMethod.Post, postPath ?? path) { Content = new FormUrlEncodedContent(form) };
        return await SendAsync(request, ct);
    }

    private async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        if (_cookies.Count > 0)
            request.Headers.Add("Cookie", string.Join("; ", _cookies.Select(pair => $"{pair.Key}={pair.Value}")));
        var response = await _client.SendAsync(request, ct);
        if (response.Headers.TryGetValues("Set-Cookie", out var setCookies))
        {
            foreach (var setCookie in setCookies)
            {
                var first = setCookie.Split(';')[0];
                var separator = first.IndexOf('=');
                var name = first[..separator];
                var value = first[(separator + 1)..];
                if (value.Length == 0 || setCookie.Contains("expires=Thu, 01 Jan 1970", StringComparison.OrdinalIgnoreCase))
                    _cookies.Remove(name);
                else
                    _cookies[name] = value;
            }
        }
        Html = await response.Content.ReadAsStringAsync(ct);
        return response;
    }
}
