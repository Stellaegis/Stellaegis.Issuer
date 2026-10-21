using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Stellaegis.Issuer.Client;
using Stellaegis.Primitives;
using Stellaegis.Primitives.AspNetCore;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Issuer.Tests;

/// <summary>The token the client of the issuer presents, fixed by the test: the issuer's header authentication reads a bearer as a service holding every operation.</summary>
internal sealed class StaticIssuerToken(string? token) : IIssuerClientTokenProvider
{
    public ValueTask<string?> GetTokenAsync(CancellationToken cancellationToken = default) => ValueTask.FromResult(token);
}

/// <summary>A clock the tests move by hand.</summary>
internal sealed class ManualClock(DateTimeOffset now) : TimeProvider
{
    private DateTimeOffset _now = now;

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan by) => _now += by;
}

/// <summary>
/// A resource server apart from the issuer, on its own test server: it validates the bearer tokens of the issuer
/// through the discovery document, reads the revoked tokens from the issuer's route, and refuses them at the door.
/// Every call to the issuer goes through the issuer's test server.
/// </summary>
internal static class ResourceServerTestHost
{
    public const string IssuerClientToken = "resource-server";

    public static async Task<WebApplication> StartAsync(
        WebApplication issuer,
        CancellationToken ct,
        string[]? audiences = null,
        SecurityKey? decryptionKey = null,
        TimeSpan? reconcileInterval = null,
        string? issuerClientToken = IssuerClientToken)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Services.AddStellaegisFrame(ApplicationFrame.WithoutCompartments);
        builder.Services.AddStellaegisBearer(options =>
        {
            options.Authority = "http://localhost";
            options.Audiences = audiences ?? ["documents"];
            options.RequireHttpsMetadata = false;
        });
        builder.Services.Configure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, jwt =>
        {
            jwt.BackchannelHttpHandler = issuer.GetTestServer().CreateHandler();
            if (decryptionKey is not null)
                jwt.TokenValidationParameters.TokenDecryptionKey = decryptionKey;
        });
        builder.Services.AddStellaegisIssuerAdmission(options => options.ReconcileInterval = reconcileInterval ?? TimeSpan.Zero);
        if (issuerClientToken is not null)
            builder.Services.AddSingleton<IIssuerClientTokenProvider>(new StaticIssuerToken(issuerClientToken));
        builder.Services.AddStellaegisIssuerClient(options => options.BaseUrl = "http://localhost/api/admin/issuer")
            .ConfigurePrimaryHttpMessageHandler(() => issuer.GetTestServer().CreateHandler());

        var app = builder.Build();
        app.UseAuthentication();
        app.UseStellaegisActorAdmission();
        app.UseAuthorization();
        app.MapGet("/ping", (System.Security.Claims.ClaimsPrincipal user) => Results.Ok(new Pong(
                user.FindFirst("sub")?.Value ?? "",
                user.FindAll("scope").Select(claim => claim.Value).ToArray())))
            .RequireAuthorization();
        await app.StartAsync(ct);
        return app;
    }

    public static HttpClient ClientWithBearer(this WebApplication app, string token)
    {
        var client = app.GetTestClient();
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    /// <summary>What a reading of the revoked tokens does, without waiting for the interval.</summary>
    public static Task ReconcileAsync(this WebApplication app, CancellationToken ct)
        => app.Services.GetServices<Microsoft.Extensions.Hosting.IHostedService>().OfType<RevokedTokensReconciliation>().Single().ReadAsync(atStartup: false, ct);

    public static RevokedTokens RevokedTokens(this WebApplication app) => app.Services.GetRequiredService<RevokedTokens>();
}

internal sealed record Pong(string Subject, string[] Scopes);
