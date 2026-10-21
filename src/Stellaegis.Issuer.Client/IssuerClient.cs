using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Stellaegis.Primitives;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Issuer.Client;

/// <summary>
/// The options of a resource server reaching the host that holds the issuer, bound from
/// <c>Stellaegis:Issuer:Client</c>: the address of its administration routes, under which
/// <c>security/revoked-tokens</c> is read.
/// <code>
/// Stellaegis:Issuer:Client:BaseUrl = https://id.internal/api/admin/issuer
/// </code>
/// </summary>
public sealed class IssuerClientOptions : StellaegisClientOptions
{
    /// <summary>The configuration section of the options, <c>Stellaegis:Issuer:Client</c>.</summary>
    public const string SectionName = "Stellaegis:Issuer:Client";
}

/// <summary>
/// Gives the client the bearer token it presents to the issuer's administration routes. <c>AddStellaegisIssuerM2M</c>
/// registers one over the client credentials of the host, for the scope <c>issuer</c>; a host that authenticates
/// otherwise registers its own. Without one registered, the client presents no token.
/// </summary>
public interface IIssuerClientTokenProvider
{
    /// <summary>The token to present, or <see langword="null"/> for none.</summary>
    ValueTask<string?> GetTokenAsync(CancellationToken cancellationToken = default);
}

/// <summary>The revoked tokens read over HTTP from <c>GET security/revoked-tokens</c> of the host that holds the issuer.</summary>
internal sealed class HttpRevokedTokensSource(HttpClient http, IServiceProvider services) : IRevokedTokensSource
{
    private readonly IIssuerClientTokenProvider? _tokens = Guard.NotNull(services).GetService<IIssuerClientTokenProvider>();

    public async Task<IReadOnlyCollection<RevokedToken>> GetRevokedTokensAsync(CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "security/revoked-tokens");
        if (_tokens is not null && await _tokens.GetTokenAsync(cancellationToken).ConfigureAwait(false) is { } token)
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (await response.ReadErrorAsync(cancellationToken).ConfigureAwait(false) is { } error)
            throw new HttpRequestException($"The issuer answered {error.Code}: {error.Message}", null, response.StatusCode);
        return await response.Content.ReadFromJsonAsync<RevokedToken[]>(cancellationToken).ConfigureAwait(false) ?? [];
    }
}

/// <summary>Registers the HTTP source of the revoked tokens.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="IRevokedTokensSource"/> over HTTP, its options bound from <paramref name="sectionName"/>
    /// and validated at startup, for the admission of the revoked tokens on a resource server apart
    /// (<see cref="AdmissionServiceCollectionExtensions.AddStellaegisIssuerAdmission(IServiceCollection, IConfiguration, string)"/>).
    /// Register an <see cref="IIssuerClientTokenProvider"/> before when the routes ask a token —
    /// <c>AddStellaegisIssuerM2M</c> does.
    /// </summary>
    /// <returns>The builder of the underlying HTTP client, to add handlers to.</returns>
    public static IHttpClientBuilder AddStellaegisIssuerClient(this IServiceCollection services, IConfiguration configuration, string sectionName = IssuerClientOptions.SectionName)
    {
        Guard.NotNull(services);
        Guard.NotNull(configuration);
        return services.AddStellaegisHttpClient<IRevokedTokensSource, HttpRevokedTokensSource, IssuerClientOptions>(configuration, sectionName);
    }

    /// <summary>
    /// Registers the HTTP source as <see cref="AddStellaegisIssuerClient(IServiceCollection, IConfiguration, string)"/>
    /// does, with its options configured in code.
    /// </summary>
    public static IHttpClientBuilder AddStellaegisIssuerClient(this IServiceCollection services, Action<IssuerClientOptions> configure)
    {
        Guard.NotNull(services);
        Guard.NotNull(configure);
        return services.AddStellaegisHttpClient<IRevokedTokensSource, HttpRevokedTokensSource, IssuerClientOptions>(configure);
    }
}
