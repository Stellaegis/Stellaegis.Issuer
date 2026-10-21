using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Stellaegis.Primitives;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Issuer.Client;

/// <summary>
/// The credentials a service speaks with, bound from <c>Stellaegis:Issuer:M2M</c> or configured in code, and
/// validated when the host starts: the confidential client the installation provisioned for it, and where the
/// issuer is.
/// <code>
/// Stellaegis:Issuer:M2M:Authority = https://id.acme.example
/// Stellaegis:Issuer:M2M:ClientId = documents
/// Stellaegis:Issuer:M2M:ClientSecret = …                                  (from a secret store)
/// </code>
/// </summary>
public sealed class IssuerM2MOptions : IValidatableOptions
{
    /// <summary>The configuration section of the options, <c>Stellaegis:Issuer:M2M</c>.</summary>
    public const string SectionName = "Stellaegis:Issuer:M2M";

    /// <summary>The issuer, an absolute http or https URL, under which the token route is reached. Required.</summary>
    public string Authority { get; set; } = string.Empty;

    /// <summary>The path of the token route under <see cref="Authority"/>. <c>/connect/token</c> unless set.</summary>
    public string TokenPath { get; set; } = "/connect/token";

    /// <summary>The id of the confidential client this service is. Required.</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>Its secret, from a secret store. Required.</summary>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>How long each call to the token route may take. Ten seconds unless set.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(10);

    /// <inheritdoc/>
    public string? FindError()
    {
        if (!Uri.TryCreate(Authority, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            return $"{nameof(Authority)} is required, as an absolute http or https URL.";
        if (string.IsNullOrWhiteSpace(TokenPath) || !TokenPath.StartsWith('/'))
            return $"{nameof(TokenPath)} is a path under the authority, starting with '/'.";
        if (string.IsNullOrWhiteSpace(ClientId))
            return $"{nameof(ClientId)} is required.";
        if (string.IsNullOrWhiteSpace(ClientSecret))
            return $"{nameof(ClientSecret)} is required.";
        if (Timeout <= TimeSpan.Zero)
            return $"{nameof(Timeout)} must be positive.";
        return null;
    }
}

/// <summary>
/// Obtains the access tokens a service speaks with, by the <c>client_credentials</c> grant, and keeps each for
/// 80 % of its lifetime so that the token route is reached once per scope and not once per call. Use it directly
/// when a raw token is needed — a SignalR connection —, or through <see cref="M2MTokenHandler"/> on an HTTP client.
/// </summary>
public sealed class M2MTokenProvider(IHttpClientFactory httpClients, IOptions<IssuerM2MOptions> options, TimeProvider clock)
{
    /// <summary>The named <see cref="HttpClient"/> the token route is reached with, for a host to configure.</summary>
    public const string HttpClientName = "Stellaegis.Issuer.M2M";

    private readonly ConcurrentDictionary<string, (string Token, DateTimeOffset ExpiresAt)> _tokens = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _lock = new(1, 1);

    /// <summary>
    /// A token for <paramref name="scope"/> — the name of the module called —, from the cache when it has one not
    /// about to expire, from the issuer otherwise.
    /// </summary>
    /// <exception cref="InvalidOperationException">The issuer refused the credentials or the scope.</exception>
    public async Task<string> GetTokenAsync(string scope, CancellationToken cancellationToken = default)
    {
        Guard.NotWhiteSpace(scope);
        if (_tokens.TryGetValue(scope, out var cached) && cached.ExpiresAt > clock.GetUtcNow())
            return cached.Token;

        await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_tokens.TryGetValue(scope, out cached) && cached.ExpiresAt > clock.GetUtcNow())
                return cached.Token;
            var (token, lifetime) = await RequestAsync(scope, cancellationToken).ConfigureAwait(false);
            _tokens[scope] = (token, clock.GetUtcNow() + lifetime * 0.8);
            return token;
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <summary>Forgets the tokens cached, so that the next call reaches the issuer: what a host does when its secret was rotated.</summary>
    public void Clear() => _tokens.Clear();

    private async Task<(string Token, TimeSpan Lifetime)> RequestAsync(string scope, CancellationToken cancellationToken)
    {
        var o = options.Value;
        var http = httpClients.CreateClient(HttpClientName);
        http.Timeout = o.Timeout;
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = o.ClientId,
            ["client_secret"] = o.ClientSecret,
            ["scope"] = scope,
        };
        using var response = await http.PostAsync(o.Authority.TrimEnd('/') + o.TokenPath, new FormUrlEncodedContent(form), cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadFromJsonAsync<TokenResponse>(cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode || body?.AccessToken is not { Length: > 0 } token)
        {
            throw new InvalidOperationException(
                $"The issuer refused the client credentials of {o.ClientId} for the scope '{scope}' (HTTP {(int)response.StatusCode}"
                + (body?.Error is { } error ? $", {error}: {body.ErrorDescription}" : "") + ").");
        }
        return (token, body.ExpiresIn > 0 ? TimeSpan.FromSeconds(body.ExpiresIn) : TimeSpan.FromMinutes(5));
    }

    private sealed record TokenResponse(
        [property: JsonPropertyName("access_token")] string? AccessToken,
        [property: JsonPropertyName("expires_in")] int ExpiresIn,
        [property: JsonPropertyName("error")] string? Error,
        [property: JsonPropertyName("error_description")] string? ErrorDescription);
}

/// <summary>
/// Attaches to every request of an HTTP client the token of <see cref="M2MTokenProvider"/> for one scope — the
/// name of the module the client calls. One handler per client, by <see cref="M2MServiceCollectionExtensions.AddM2MToken"/>.
/// </summary>
public sealed class M2MTokenHandler(M2MTokenProvider tokens, string scope) : DelegatingHandler
{
    private readonly string _scope = Guard.NotWhiteSpace(scope);

    /// <inheritdoc/>
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Guard.NotNull(request);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await tokens.GetTokenAsync(_scope, cancellationToken).ConfigureAwait(false));
        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>The token the HTTP source of the revoked tokens presents to the issuer: the host's own credentials, for the scope <c>issuer</c>.</summary>
internal sealed class M2MIssuerClientTokenProvider(M2MTokenProvider tokens) : IIssuerClientTokenProvider
{
    /// <summary>The scope the issuer's administration routes are called with: the issuer module's name.</summary>
    public const string Scope = "issuer";

    public async ValueTask<string?> GetTokenAsync(CancellationToken cancellationToken = default)
        => await tokens.GetTokenAsync(Scope, cancellationToken).ConfigureAwait(false);
}

/// <summary>Registers the credentials a service speaks with.</summary>
public static class M2MServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="M2MTokenProvider"/> with its options bound from <paramref name="sectionName"/> and
    /// validated at startup, the named HTTP client it reaches the issuer with, and an
    /// <see cref="IIssuerClientTokenProvider"/> over it for the HTTP source of the revoked tokens — unless the host
    /// registered one before.
    /// </summary>
    public static IServiceCollection AddStellaegisIssuerM2M(this IServiceCollection services, IConfiguration configuration, string sectionName = IssuerM2MOptions.SectionName)
    {
        Guard.NotNull(services);
        Guard.NotNull(configuration);
        services.AddStellaegisOptions<IssuerM2MOptions>(configuration, sectionName);
        return services.AddM2M();
    }

    /// <summary>
    /// Registers the credentials as <see cref="AddStellaegisIssuerM2M(IServiceCollection, IConfiguration, string)"/>
    /// does, their options configured in code.
    /// </summary>
    public static IServiceCollection AddStellaegisIssuerM2M(this IServiceCollection services, Action<IssuerM2MOptions> configure)
    {
        Guard.NotNull(services);
        Guard.NotNull(configure);
        services.AddStellaegisOptions(configure);
        return services.AddM2M();
    }

    private static IServiceCollection AddM2M(this IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.AddHttpClient(M2MTokenProvider.HttpClientName);
        services.TryAddSingleton<M2MTokenProvider>();
        services.TryAddSingleton<IIssuerClientTokenProvider, M2MIssuerClientTokenProvider>();
        return services;
    }

    /// <summary>
    /// Attaches the host's token for <paramref name="scope"/> — the name of the module the client calls — to every
    /// request of the HTTP client being built: <c>services.AddStellaegisHttpClient&lt;…&gt;(…).AddM2MToken("documents")</c>.
    /// Requires <see cref="AddStellaegisIssuerM2M(IServiceCollection, IConfiguration, string)"/>.
    /// </summary>
    public static IHttpClientBuilder AddM2MToken(this IHttpClientBuilder builder, string scope)
    {
        Guard.NotNull(builder);
        Guard.NotWhiteSpace(scope);
        return builder.AddHttpMessageHandler(provider => new M2MTokenHandler(provider.GetRequiredService<M2MTokenProvider>(), scope));
    }
}
