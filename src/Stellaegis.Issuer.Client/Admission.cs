using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Stellaegis.Primitives;
using Stellaegis.Primitives.AspNetCore;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Issuer.Client;

/// <summary>
/// The options of the admission of the revoked tokens on a resource server, bound from
/// <c>Stellaegis:Issuer:Admission</c>: how often the revoked tokens are read again from their source.
/// <code>
/// Stellaegis:Issuer:Admission:ReconcileInterval = 00:02:00
/// </code>
/// </summary>
public sealed class IssuerAdmissionOptions : IValidatableOptions
{
    /// <summary>The configuration section of the options, <c>Stellaegis:Issuer:Admission</c>.</summary>
    public const string SectionName = "Stellaegis:Issuer:Admission";

    /// <summary>
    /// How often the revoked tokens are read again from <see cref="IRevokedTokensSource"/>, after the reading at
    /// startup: the safety net for an event lost between the host and the issuer. Two minutes unless set;
    /// <see cref="TimeSpan.Zero"/> reads once, at startup.
    /// </summary>
    public TimeSpan ReconcileInterval { get; set; } = TimeSpan.FromMinutes(2);

    /// <inheritdoc/>
    public string? FindError() => ReconcileInterval < TimeSpan.Zero ? $"{nameof(ReconcileInterval)} is zero or positive." : null;
}

/// <summary>
/// Reads the revoked tokens from their source when the host starts — a restarted host would otherwise admit every
/// token until the first event —, then every <see cref="IssuerAdmissionOptions.ReconcileInterval"/>. A source out
/// of reach is logged as critical and tried again at the next interval: the host keeps serving, with the tokens
/// it knows, rather than stopping for a dependency that is down.
/// </summary>
internal sealed class RevokedTokensReconciliation(
    IServiceProvider services,
    RevokedTokens tokens,
    IOptions<IssuerAdmissionOptions> options,
    ILogger<RevokedTokensReconciliation> logger) : IHostedService, IAsyncDisposable
{
    private CancellationTokenSource? _loopCancellation;
    private Task? _loop;

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        using (var scope = services.CreateScope())
        {
            if (scope.ServiceProvider.GetService<IRevokedTokensSource>() is null)
            {
                throw new InvalidOperationException(
                    "The admission of the revoked tokens is registered, and no source of them is: nothing would ever be refused. "
                    + "On the host that holds the issuer, AddStellaegisIssuer registers the local source; on a resource server apart, "
                    + "register the HTTP source of Stellaegis.Issuer.Client, AddStellaegisIssuerClient(...).");
            }
        }

        await ReadAsync(atStartup: true, cancellationToken).ConfigureAwait(false);
        var interval = options.Value.ReconcileInterval;
        if (interval > TimeSpan.Zero)
        {
            _loopCancellation = new CancellationTokenSource();
            _loop = LoopAsync(interval, _loopCancellation.Token);
        }
    }

    private async Task LoopAsync(TimeSpan interval, CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(interval);
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
                await ReadAsync(atStartup: false, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // The host stops.
        }
    }

    internal async Task ReadAsync(bool atStartup, CancellationToken cancellationToken)
    {
        try
        {
            using var scope = services.CreateScope();
            var source = scope.ServiceProvider.GetRequiredService<IRevokedTokensSource>();
            var revoked = await source.GetRevokedTokensAsync(cancellationToken).ConfigureAwait(false);
            tokens.Replace(revoked);
            if (atStartup)
                logger.LogInformation("Revoked tokens read at startup: {Count}", revoked.Count);
            else
                logger.LogDebug("Revoked tokens read again: {Count}", revoked.Count);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // The host stops.
        }
        catch (Exception exception)
        {
            logger.LogCritical(exception,
                "The revoked tokens could not be read: a token revoked since the last reading is admitted until the next one succeeds.");
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        if (_loopCancellation is not null)
            await _loopCancellation.CancelAsync().ConfigureAwait(false);
        if (_loop is not null)
        {
            try
            {
                await _loop.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Best effort while stopping.
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_loopCancellation is not null)
        {
            await _loopCancellation.CancelAsync().ConfigureAwait(false);
            _loopCancellation.Dispose();
        }
    }
}

/// <summary>Registers the admission of the revoked tokens on a resource server.</summary>
public static class AdmissionServiceCollectionExtensions
{
    /// <summary>
    /// Registers the admission of the revoked tokens: <see cref="RevokedTokens"/> kept in memory, read from
    /// <see cref="IRevokedTokensSource"/> at startup and then periodically, its options bound from
    /// <paramref name="sectionName"/>; and the <see cref="IActorAdmission"/> of the issuer, beside those of the
    /// other modules. The host registers the source that fits it — the issuer's own, or the HTTP one —, enables
    /// the admission on its pipeline with <c>UseStellaegisActorAdmission()</c> of Primitives, and connects its bus
    /// to <see cref="RevokedTokens.Revoke"/> so that a revocation from another host applies without waiting for
    /// the next reading.
    /// </summary>
    public static IServiceCollection AddStellaegisIssuerAdmission(this IServiceCollection services, IConfiguration configuration, string sectionName = IssuerAdmissionOptions.SectionName)
    {
        Guard.NotNull(services);
        Guard.NotNull(configuration);
        services.AddStellaegisOptions<IssuerAdmissionOptions>(configuration, sectionName);
        return Admission(services);
    }

    /// <summary>
    /// Registers the admission of the revoked tokens as <see cref="AddStellaegisIssuerAdmission(IServiceCollection, IConfiguration, string)"/>
    /// does, with its options configured in code — the defaults unless <paramref name="configure"/> changes them.
    /// </summary>
    public static IServiceCollection AddStellaegisIssuerAdmission(this IServiceCollection services, Action<IssuerAdmissionOptions>? configure = null)
    {
        Guard.NotNull(services);
        services.AddStellaegisOptions<IssuerAdmissionOptions>(configure ?? (_ => { }));
        return Admission(services);
    }

    private static IServiceCollection Admission(IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<RevokedTokens>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, RevokedTokensReconciliation>());
        if (!services.Any(descriptor => descriptor.ServiceType == typeof(AdmissionRegistered)))
        {
            services.AddSingleton(AdmissionRegistered.Instance);
            services.AddStellaegisActorAdmission(provider => provider.GetRequiredService<RevokedTokens>());
        }
        return services;
    }

    private sealed class AdmissionRegistered
    {
        public static readonly AdmissionRegistered Instance = new();
    }
}
