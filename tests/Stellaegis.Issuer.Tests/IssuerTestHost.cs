using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Base64UrlTextEncoder = Microsoft.AspNetCore.WebUtilities.Base64UrlTextEncoder;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Stellaegis.Issuer.Client;
using Stellaegis.Primitives;
using Stellaegis.Primitives.AspNetCore;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Issuer.Tests;

/// <summary>Keeps every event published, so that a test reads what the issuer said.</summary>
internal sealed class CapturingEventPublisher : IEventPublisher
{
    public List<IEvent> Events { get; } = [];

    public Task PublishAsync<TEvent>(TEvent @event, CancellationToken cancellationToken = default) where TEvent : IEvent
    {
        Events.Add(@event);
        return Task.CompletedTask;
    }
}

/// <summary>An admission of the host: refuses the subjects a test names, the way the blocked accounts of Identity would.</summary>
internal sealed class RefusingSubjects : IActorAdmission
{
    public HashSet<string> Refused { get; } = new(StringComparer.Ordinal);

    public ValueTask<Result> AdmitAsync(ClaimsPrincipal principal, CancellationToken cancellationToken)
    {
        var subject = principal.FindFirst("sub")?.Value ?? principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        return ValueTask.FromResult(subject is not null && Refused.Contains(subject)
            ? Result.Failure(Error.Unauthorized("Account.Blocked", "The account is blocked."))
            : Result.Success());
    }
}

/// <summary>
/// The authentication of the host, read from headers: <c>X-Subject</c> names the person signed in, with
/// <c>X-Email</c>, <c>X-Name</c> and <c>X-Grants</c> for the operations granted; <c>Authorization: Bearer</c> names
/// a service, every operation granted; a challenge answers 401; a sign-out is recorded. What the cookie of Identity
/// or Negotiate would be for the issuer, and what the bearer of a resource server would be for its routes.
/// </summary>
internal sealed class HeaderAuthentication(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder), IAuthenticationSignOutHandler
{
    public const string SchemeName = "Header";
    public const string GrantClaim = "grant";

    public static int SignOuts;

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        string? subject = null;
        IEnumerable<string> grants = [];
        if (Request.Headers.TryGetValue("X-Subject", out var given) && !string.IsNullOrWhiteSpace(given))
        {
            subject = given.ToString();
            grants = Request.Headers.TryGetValue("X-Grants", out var granted)
                ? granted.ToString().Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                : [];
        }
        else if (System.Net.Http.Headers.AuthenticationHeaderValue.TryParse(Request.Headers.Authorization, out var bearer) && bearer.Scheme == "Bearer" && bearer.Parameter is { } token)
        {
            subject = token;
            grants = IssuerOperations.All.Select(operation => operation.ToString());
        }
        if (subject is null)
            return Task.FromResult(AuthenticateResult.NoResult());
        var claims = new List<Claim> { new("sub", subject), new(ClaimTypes.NameIdentifier, subject) };
        if (Request.Headers.TryGetValue("X-Email", out var email))
            claims.Add(new Claim("email", email.ToString()));
        if (Request.Headers.TryGetValue("X-Name", out var name))
            claims.Add(new Claim("name", name.ToString()));
        if (Request.Headers.TryGetValue("X-Amr", out var methods))
            claims.AddRange(methods.ToString().Split(' ', StringSplitOptions.RemoveEmptyEntries).Select(method => new Claim("amr", method)));
        claims.AddRange(grants.Select(grant => new Claim(GrantClaim, grant)));
        var identity = new ClaimsIdentity(claims, SchemeName);
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
    }

    public Task SignOutAsync(AuthenticationProperties? properties)
    {
        Interlocked.Increment(ref SignOuts);
        return Task.CompletedTask;
    }
}

/// <summary>
/// The issuer assembled on the test server, its stores on a SQLite database in memory — the EF Core in-memory
/// provider cannot delete in bulk, which the OpenIddict stores do —, signing with development certificates.
/// </summary>
internal static class IssuerTestHost
{
    public const string RedirectUri = "http://127.0.0.1:7890/";

    public static WebApplicationBuilder Builder(Action<IssuerOptions>? configure = null, string? environment = null)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = environment ?? Environments.Development });
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        builder.Services.AddSingleton(connection);
        builder.Services.AddStellaegisFrame(ApplicationFrame.WithoutCompartments);
        builder.Services.AddSingleton<IEventPublisher, CapturingEventPublisher>();
        builder.Services.AddSingleton<RefusingSubjects>();
        builder.Services.AddStellaegisActorAdmission(provider => provider.GetRequiredService<RefusingSubjects>());
        builder.Services.AddTestAuthentication();
        builder.Services.AddStellaegisIssuer(options =>
        {
            options.Certificates.UseDevelopmentCertificates = true;
            options.RequireHttps = false;
            options.EncryptAccessTokens = false;
            configure?.Invoke(options);
        }, db => db.UseSqlite(connection).ConfigureWarnings(warnings => warnings.Ignore(RelationalEventId.AmbientTransactionWarning)));
        builder.Services.AddStellaegisIssuerAdmission();
        return builder;
    }

    /// <summary>
    /// Builds and starts the host. The admission at the door is off unless <paramref name="door"/>: it would refuse a
    /// blocked person before the authorization route sends the client <c>access_denied</c>, which is what the flow
    /// tests look at. The SQLite database is created by EF Core unless <paramref name="ensureCreated"/> is off —
    /// the PostgreSQL tests install theirs from the frozen script, and prove that EF Core never has to.
    /// </summary>
    public static async Task<WebApplication> StartAsync(this WebApplicationBuilder builder, CancellationToken ct, bool door = false, bool ensureCreated = true, Action<WebApplication>? map = null)
    {
        var app = builder.Build();
        if (ensureCreated)
        {
            using var scope = app.Services.CreateScope();
            await scope.ServiceProvider.GetRequiredService<IssuerDbContext>().Database.EnsureCreatedAsync(ct);
        }
        app.UseAuthentication();
        if (door)
            app.UseStellaegisActorAdmission();
        app.UseAuthorization();
        app.MapStellaegisIssuer();
        app.MapGroup("/api/admin").MapIssuerAdminEndpoints().RequireAuthorizationPerOperation(operation => operation.ToString());
        map?.Invoke(app);
        await app.StartAsync(ct);
        return app;
    }

    /// <summary>The header authentication, one policy per operation of the module requiring its grant, and the startup check of the administration routes.</summary>
    public static IServiceCollection AddTestAuthentication(this IServiceCollection services)
    {
        services.AddAuthentication(HeaderAuthentication.SchemeName)
            .AddScheme<AuthenticationSchemeOptions, HeaderAuthentication>(HeaderAuthentication.SchemeName, null);
        services.AddAuthorization(options =>
        {
            foreach (var operation in IssuerOperations.All)
                options.AddPolicy(operation.ToString(), policy => policy.RequireClaim(HeaderAuthentication.GrantClaim, operation.ToString()));
        });
        services.AddStellaegisIssuerAdministration();
        return services;
    }

    /// <summary>Every operation of the module, as grants.</summary>
    public static readonly string[] Everything = IssuerOperations.All.Select(operation => operation.ToString()).ToArray();

    /// <summary>A client of the host calling as <paramref name="subject"/>, holding <paramref name="grants"/> — apart from <see cref="ClientAs"/>, whose second argument is an e-mail.</summary>
    public static HttpClient ClientHolding(this WebApplication app, string subject, params string[] grants)
    {
        var client = app.GetTestClient();
        client.DefaultRequestHeaders.Add("X-Subject", subject);
        if (grants.Length > 0)
            client.DefaultRequestHeaders.Add("X-Grants", string.Join(",", grants));
        return client;
    }

    /// <summary>The code of the problem details a route answered, or <see langword="null"/>.</summary>
    public static async Task<string?> CodeOfAsync(this HttpResponseMessage response, CancellationToken ct)
    {
        var problem = await response.Content.ReadFromJsonAsync<ProblemBody>(ct);
        return problem?.Code;
    }

    private sealed record ProblemBody(string? Code);

    /// <summary>A public client, <c>desktop</c>, allowed the scope <paramref name="scope"/>, and that scope with itself as resource.</summary>
    public static async Task DeclarePublicClientAsync(this WebApplication app, string clientId = "desktop", string scope = "documents", CancellationToken ct = default, ClientKind kind = ClientKind.Public, string redirectUri = RedirectUri)
    {
        using var services = app.Services.CreateScope();
        var catalog = services.ServiceProvider.GetRequiredService<IssuerCatalog>();
        if ((await catalog.GetScopeAsync(scope, ct)).IsFailure)
            Assert.True((await catalog.CreateScopeAsync(new ScopeDefinition(scope), ct)).IsSuccess);
        var created = await catalog.CreateClientAsync(new ClientDefinition(clientId, Kind: kind, Scopes: ["email", "profile", scope], RedirectUris: [redirectUri]), ct);
        Assert.True(created.IsSuccess, created.Error?.ToString());
    }

    public static CapturingEventPublisher Events(this WebApplication app) => (CapturingEventPublisher)app.Services.GetRequiredService<IEventPublisher>();

    public static RefusingSubjects Refusing(this WebApplication app) => app.Services.GetRequiredService<RefusingSubjects>();

    public static HttpClient ClientAs(this WebApplication app, string? subject, string? email = null, string? name = null, string? amr = null)
    {
        var client = app.GetTestClient();
        if (subject is not null)
            client.DefaultRequestHeaders.Add("X-Subject", subject);
        if (email is not null)
            client.DefaultRequestHeaders.Add("X-Email", email);
        if (name is not null)
            client.DefaultRequestHeaders.Add("X-Name", name);
        if (amr is not null)
            client.DefaultRequestHeaders.Add("X-Amr", amr);
        return client;
    }

    /// <summary>A PKCE verifier and its S256 challenge.</summary>
    public static (string Verifier, string Challenge) Pkce()
    {
        var verifier = Base64UrlTextEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        var challenge = Base64UrlTextEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        return (verifier, challenge);
    }

    public static string AuthorizeUrl(string clientId, string challenge, string scope = "openid offline_access email profile documents", string state = "s1", string redirectUri = RedirectUri)
        => QueryHelpers.AddQueryString(IssuerEndpoints.AuthorizePath, new Dictionary<string, string?>
        {
            ["client_id"] = clientId,
            ["redirect_uri"] = redirectUri,
            ["response_type"] = "code",
            ["scope"] = scope,
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["state"] = state,
        });

    /// <summary>Walks the authorization for <paramref name="subject"/> and returns the code of the redirect.</summary>
    public static async Task<(string Code, string Verifier)> AuthorizeAsync(this WebApplication app, string subject, string clientId = "desktop", CancellationToken ct = default, string? amr = null)
    {
        var (verifier, challenge) = Pkce();
        using var client = app.ClientAs(subject, email: $"{subject}@acme.test", name: subject, amr: amr);
        var response = await client.GetAsync(AuthorizeUrl(clientId, challenge), ct);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location!;
        Assert.StartsWith(RedirectUri, location.ToString());
        var query = QueryHelpers.ParseQuery(location.Query);
        Assert.False(query.ContainsKey("error"), query.TryGetValue("error_description", out var description) ? description.ToString() : "error");
        return (query["code"].ToString(), verifier);
    }

    public static async Task<TokenResponse> ExchangeCodeAsync(this WebApplication app, string code, string verifier, string clientId = "desktop", CancellationToken ct = default)
        => await app.TokenAsync(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = clientId,
            ["code"] = code,
            ["code_verifier"] = verifier,
            ["redirect_uri"] = RedirectUri,
        }, ct);

    public static async Task<TokenResponse> RefreshAsync(this WebApplication app, string refreshToken, string clientId = "desktop", CancellationToken ct = default)
        => await app.TokenAsync(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = clientId,
            ["refresh_token"] = refreshToken,
        }, ct);

    public static async Task<TokenResponse> ClientCredentialsAsync(this WebApplication app, string clientId, string secret, string scope, CancellationToken ct = default)
        => await app.TokenAsync(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = clientId,
            ["client_secret"] = secret,
            ["scope"] = scope,
        }, ct);

    public static async Task<TokenResponse> TokenAsync(this WebApplication app, Dictionary<string, string> form, CancellationToken ct)
    {
        using var client = app.GetTestClient();
        var response = await client.PostAsync(IssuerEndpoints.TokenPath, new FormUrlEncodedContent(form), ct);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(ct);
        return new TokenResponse(response.StatusCode, body);
    }

    /// <summary>The payload of a signed token, as JSON.</summary>
    public static JsonElement Payload(string jwt)
    {
        var parts = jwt.Split('.');
        Assert.Equal(3, parts.Length);
        return JsonDocument.Parse(Base64UrlTextEncoder.Decode(parts[1])).RootElement;
    }
}

internal sealed record TokenResponse(HttpStatusCode Status, JsonElement Body)
{
    public string Get(string name) => Body.TryGetProperty(name, out var value) ? value.GetString() ?? "" : "";

    public string AccessToken => Get("access_token");

    public string RefreshToken => Get("refresh_token");

    public string IdToken => Get("id_token");

    public string Error => Get("error");

    public string ErrorDescription => Get("error_description");
}
