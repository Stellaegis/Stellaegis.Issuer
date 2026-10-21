using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Stellaegis.Issuer.Client;

namespace Stellaegis.Issuer.Tests;

/// <summary>The credentials a service speaks with: the token obtained, kept, attached.</summary>
public sealed class M2MTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static async Task<(WebApplication Issuer, string Secret)> IssuerWithModuleAsync()
    {
        var issuer = await IssuerTestHost.Builder().StartAsync(Ct);
        using var scope = issuer.Services.CreateScope();
        var provisioned = await scope.ServiceProvider.GetRequiredService<IOidcClientProvisioner>().ProvisionModuleClientAsync("documents", Ct);
        Assert.True(provisioned.IsSuccess, provisioned.Error?.ToString());
        // The installation lets the service call the issuer's routes: the scope of the issuer module, granted to the client.
        var catalog = scope.ServiceProvider.GetRequiredService<IssuerCatalog>();
        Assert.True((await catalog.CreateScopeAsync(new ScopeDefinition("issuer"), Ct)).IsSuccess);
        Assert.True((await catalog.UpdateClientAsync(new ClientDefinition("documents", Kind: ClientKind.Confidential, Scopes: ["documents", "issuer"]), Ct)).IsSuccess);
        return (issuer, provisioned.Value.Secret);
    }

    private static ServiceProvider ServiceOf(WebApplication issuer, string secret, ManualClock? clock = null, Action<IServiceCollection>? more = null)
    {
        var services = new ServiceCollection();
        if (clock is not null)
            services.AddSingleton<TimeProvider>(clock);
        services.AddStellaegisIssuerM2M(options =>
        {
            options.Authority = "http://localhost";
            options.ClientId = "documents";
            options.ClientSecret = secret;
        });
        services.AddHttpClient(M2MTokenProvider.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => issuer.GetTestServer().CreateHandler());
        more?.Invoke(services);
        return services.BuildServiceProvider();
    }

    [Fact]
    public async Task A_service_obtains_its_token_by_its_credentials_keeps_it_and_asks_again_near_its_expiration()
    {
        var (issuer, secret) = await IssuerWithModuleAsync();
        await using var _ = issuer;
        var clock = new ManualClock(DateTimeOffset.UtcNow);
        await using var services = ServiceOf(issuer, secret, clock);
        var provider = services.GetRequiredService<M2MTokenProvider>();

        var first = await provider.GetTokenAsync("documents", Ct);
        Assert.Equal("documents", IssuerTestHost.Payload(first).GetProperty("sub").GetString());
        Assert.Same(first, await provider.GetTokenAsync("documents", Ct));                     // kept

        clock.Advance(TimeSpan.FromMinutes(9));                                                // past 80 % of the ten minutes
        var renewed = await provider.GetTokenAsync("documents", Ct);
        Assert.NotEqual(first, renewed);

        provider.Clear();
        Assert.NotEqual(renewed, await provider.GetTokenAsync("documents", Ct));

        var refused = await Assert.ThrowsAsync<InvalidOperationException>(() => provider.GetTokenAsync("nowhere", Ct));
        Assert.Contains("documents", refused.Message);
    }

    [Fact]
    public async Task The_handler_attaches_the_token_to_every_request_and_the_issuer_client_presents_it()
    {
        var (issuer, secret) = await IssuerWithModuleAsync();
        await using var _ = issuer;
        await using var services = ServiceOf(issuer, secret, more: services =>
        {
            services.AddHttpClient("issuer-admin", http => http.BaseAddress = new Uri("http://localhost/api/admin/issuer/"))
                .ConfigurePrimaryHttpMessageHandler(() => issuer.GetTestServer().CreateHandler())
                .AddM2MToken("issuer");
            services.AddStellaegisIssuerClient(options => options.BaseUrl = "http://localhost/api/admin/issuer")
                .ConfigurePrimaryHttpMessageHandler(() => issuer.GetTestServer().CreateHandler());
        });

        // The issuer's test authentication reads a bearer as a service holding every operation: a 200 proves the header.
        var client = services.GetRequiredService<IHttpClientFactory>().CreateClient("issuer-admin");
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("security/revoked-tokens", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await issuer.GetTestClient().GetAsync("/api/admin/issuer/security/revoked-tokens", Ct)).StatusCode);

        var presented = await services.GetRequiredService<IIssuerClientTokenProvider>().GetTokenAsync(Ct);
        Assert.Equal("documents", IssuerTestHost.Payload(presented!).GetProperty("sub").GetString());
        Assert.Empty(await services.GetRequiredService<IRevokedTokensSource>().GetRevokedTokensAsync(Ct));
    }

    [Fact]
    public void The_options_take_the_form_of_the_family()
    {
        Assert.Equal("Stellaegis:Issuer:M2M", IssuerM2MOptions.SectionName);
        Assert.Contains("Authority", new IssuerM2MOptions().FindError());
        Assert.Contains("ClientId", new IssuerM2MOptions { Authority = "https://id.acme.test" }.FindError());
        Assert.Contains("ClientSecret", new IssuerM2MOptions { Authority = "https://id.acme.test", ClientId = "documents" }.FindError());
        Assert.Null(new IssuerM2MOptions { Authority = "https://id.acme.test", ClientId = "documents", ClientSecret = "s" }.FindError());
    }
}
