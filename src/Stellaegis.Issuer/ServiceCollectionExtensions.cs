using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using Stellaegis.Issuer.Client;
using Stellaegis.Primitives;
using Stellaegis.Primitives.AspNetCore;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Issuer;

/// <summary>Registers the issuer.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the issuer: OpenIddict as the server — authorization code with PKCE, client credentials, refresh
    /// tokens, the routes under <c>/connect</c> —, its stores on <see cref="IssuerDbContext"/> over the provider
    /// <paramref name="configureDatabase"/> names, the revocation, the provisioning of clients, the catalog of
    /// clients and scopes, the local source of the revoked tokens, its options bound from
    /// <paramref name="sectionName"/> and validated when the host starts; and declares the module to the
    /// application. The host maps the protocol routes with <see cref="IssuerEndpoints.MapStellaegisIssuer"/>, the
    /// administration routes with <see cref="IssuerAdminEndpoints.MapIssuerAdminEndpoints"/>, and registers the
    /// admission of the revoked tokens with <c>AddStellaegisIssuerAdmission()</c> of <c>Stellaegis.Issuer.Client</c>.
    /// <c>Stellaegis.Issuer.PostgreSQL</c> calls this with its provider and declares the database.
    /// </summary>
    /// <param name="services">The services of the host.</param>
    /// <param name="configuration">The configuration the options are bound from.</param>
    /// <param name="configureDatabase">The provider of the stores, <c>db => db.UseNpgsql(…)</c>.</param>
    /// <param name="sectionName">The section the options are bound from, <see cref="IssuerOptions.SectionName"/> unless given.</param>
    public static IServiceCollection AddStellaegisIssuer(
        this IServiceCollection services, IConfiguration configuration, Action<DbContextOptionsBuilder> configureDatabase, string sectionName = IssuerOptions.SectionName)
    {
        Guard.NotNull(configuration);
        Guard.NotWhiteSpace(sectionName);
        var options = new IssuerOptions();
        configuration.GetSection(sectionName).Bind(options);
        services.AddStellaegisOptions<IssuerOptions>(configuration, sectionName);
        return services.AddIssuer(options, configureDatabase);
    }

    /// <summary>
    /// Registers the issuer as <see cref="AddStellaegisIssuer(IServiceCollection, IConfiguration, Action{DbContextOptionsBuilder}, string)"/>
    /// does, its options configured in code.
    /// </summary>
    public static IServiceCollection AddStellaegisIssuer(
        this IServiceCollection services, Action<IssuerOptions> configure, Action<DbContextOptionsBuilder> configureDatabase)
    {
        Guard.NotNull(configure);
        var options = new IssuerOptions();
        configure(options);
        services.AddStellaegisOptions(configure);
        return services.AddIssuer(options, configureDatabase);
    }

    private static IServiceCollection AddIssuer(this IServiceCollection services, IssuerOptions options, Action<DbContextOptionsBuilder> configureDatabase)
    {
        Guard.NotNull(services);
        Guard.NotNull(configureDatabase);
        if (options.FindError() is { } error)
            throw new InvalidOperationException($"{nameof(IssuerOptions)}: {error}");

        services.AddStellaegisIssuerModule();
        services.AddStellaegisActorAdmissions();
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IEventPublisher>(NullEventPublisher.Instance);
        services.AddOptions<IssuerOptions>().Services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<IssuerOptions>, EnvironmentValidator>());

        services.AddDbContext<IssuerDbContext>(db =>
        {
            configureDatabase(db);
            db.UseSnakeCaseNamingConvention();
            db.UseOpenIddict();
        });

        services.AddOpenIddict()
            .AddCore(core => core.UseEntityFrameworkCore().UseDbContext<IssuerDbContext>())
            .AddServer(server =>
            {
                if (options.Issuer is not null)
                    server.SetIssuer(new Uri(options.Issuer, UriKind.Absolute));

                server.SetAuthorizationEndpointUris(IssuerEndpoints.AuthorizePath)
                    .SetTokenEndpointUris(IssuerEndpoints.TokenPath)
                    .SetEndSessionEndpointUris(IssuerEndpoints.LogoutPath)
                    .SetUserInfoEndpointUris(IssuerEndpoints.UserInfoPath);

                server.AllowAuthorizationCodeFlow().RequireProofKeyForCodeExchange()
                    .AllowClientCredentialsFlow()
                    .AllowRefreshTokenFlow();

                server.SetAccessTokenLifetime(options.AccessTokenLifetime)
                    .SetIdentityTokenLifetime(options.IdentityTokenLifetime)
                    .SetAuthorizationCodeLifetime(options.AuthorizationCodeLifetime)
                    .SetRefreshTokenLifetime(options.RefreshTokenLifetime);

                if (!options.EncryptAccessTokens)
                    server.DisableAccessTokenEncryption();

                server.RegisterScopes(options.StandardScopes);

                var certificates = options.Certificates;
                if (certificates.UseDevelopmentCertificates)
                {
                    server.AddDevelopmentSigningCertificate();
                    server.AddDevelopmentEncryptionCertificate();
                }
                else
                {
                    if (certificates.Signing.IsSet)
                        server.AddSigningCertificate(certificates.Signing.Load());
                    if (certificates.Encryption.IsSet)
                        server.AddEncryptionCertificate(certificates.Encryption.Load());
                }

                server.AddEventHandler(ClientCredentialsTokenHandler.Descriptor);
                server.AddEventHandler(RefreshAdmissionHandler.Descriptor);
                server.AddEventHandler(AuthenticationMethodsHandler.Descriptor);

                var aspnet = server.UseAspNetCore()
                    .EnableAuthorizationEndpointPassthrough()
                    .EnableUserInfoEndpointPassthrough()
                    .EnableEndSessionEndpointPassthrough();
                if (!options.RequireHttps)
                    aspnet.DisableTransportSecurityRequirement();
            });

        services.TryAddScoped<ITokenRevoker, TokenRevoker>();
        services.TryAddScoped<IRevokedTokensSource, LocalRevokedTokensSource>();
        services.TryAddScoped<IOidcClientProvisioner, OpenIddictClientProvisioner>();
        services.TryAddScoped<IssuerCatalog>();
        return services;
    }

    /// <summary>
    /// What the options cannot check alone: outside the Development environment, the development certificates are
    /// refused and the real ones are required — a production issuer whose keys change at every restart invalidates
    /// every token it issued, silently.
    /// </summary>
    private sealed class EnvironmentValidator(IHostEnvironment? environment = null) : IValidateOptions<IssuerOptions>
    {
        public ValidateOptionsResult Validate(string? name, IssuerOptions options)
        {
            var development = environment?.IsDevelopment() ?? false;
            var certificates = options.Certificates;
            if (development)
                return ValidateOptionsResult.Success;
            if (certificates.UseDevelopmentCertificates)
                return ValidateOptionsResult.Fail($"{nameof(IssuerOptions)}: {nameof(IssuerOptions.Certificates)}:{nameof(IssuerCertificatesOptions.UseDevelopmentCertificates)} is accepted in the Development environment only: every restart would invalidate every token issued.");
            if (!certificates.Signing.IsSet)
                return ValidateOptionsResult.Fail($"{nameof(IssuerOptions)}: {nameof(IssuerOptions.Certificates)}:{nameof(IssuerCertificatesOptions.Signing)} is required outside Development: the certificate the tokens are signed with, from a file or from the store.");
            if (options.EncryptAccessTokens && !certificates.Encryption.IsSet)
                return ValidateOptionsResult.Fail($"{nameof(IssuerOptions)}: {nameof(IssuerOptions.Certificates)}:{nameof(IssuerCertificatesOptions.Encryption)} is required outside Development when {nameof(IssuerOptions.EncryptAccessTokens)} holds.");
            return ValidateOptionsResult.Success;
        }
    }
}
