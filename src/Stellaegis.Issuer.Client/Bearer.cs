using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Stellaegis.Primitives;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Issuer.Client;

/// <summary>
/// The options of a resource server accepting the bearer tokens the issuer issued, bound from
/// <c>Stellaegis:Issuer:Bearer</c> or configured in code, and validated when the host starts.
/// <code>
/// Stellaegis:Issuer:Bearer:Authority = https://id.acme.example
/// Stellaegis:Issuer:Bearer:Audiences:0 = documents
/// </code>
/// </summary>
/// <remarks>
/// ⚠ An access token the issuer encrypts (JWE, its default) is read by nobody but a resource server holding the
/// encryption certificate's private key, named in <see cref="Decryption"/>; a signed-only token (JWS) is validated
/// by any resource server with the public keys of the discovery document. Sharing a private key across hosts is a
/// deployment of its own: in a distributed topology, the issuer sets <c>EncryptAccessTokens = false</c>, and the
/// token stays compact — <c>sub</c>, <c>email</c>, scopes, audiences — with nothing in it worth hiding.
/// </remarks>
public sealed class IssuerBearerOptions : IValidatableOptions
{
    /// <summary>The configuration section of the options, <c>Stellaegis:Issuer:Bearer</c>.</summary>
    public const string SectionName = "Stellaegis:Issuer:Bearer";

    /// <summary>The issuer, an absolute http or https URL: where the discovery document and the keys are read from, and what every token names as <c>iss</c>. Required.</summary>
    public string Authority { get; set; } = string.Empty;

    /// <summary>
    /// The audiences this resource server accepts: the names of the modules it serves, which a token carries as
    /// <c>aud</c> when the scopes of those names were requested. At least one.
    /// </summary>
    public string[] Audiences { get; set; } = [];

    /// <summary>Whether the discovery document is read over HTTPS only. Yes unless set; a development host behind plain HTTP sets it to <see langword="false"/>.</summary>
    public bool RequireHttpsMetadata { get; set; } = true;

    /// <summary>Where the discovery document is read from, when it is not at <c>{Authority}/.well-known/openid-configuration</c>. None unless set.</summary>
    public string? MetadataAddress { get; set; }

    /// <summary>How far the clocks of the issuer and of this host may disagree. Five minutes unless set.</summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>The certificate the access tokens are decrypted with, when the issuer encrypts them (JWE). None unless set: the tokens are then signed only.</summary>
    public IssuerCertificateOptions Decryption { get; set; } = new();

    /// <inheritdoc/>
    public string? FindError()
    {
        if (!Uri.TryCreate(Authority, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            return $"{nameof(Authority)} is required, as an absolute http or https URL.";
        if (Audiences.Length == 0 || Audiences.Any(string.IsNullOrWhiteSpace))
            return $"{nameof(Audiences)} names at least one audience, the modules this host serves.";
        if (MetadataAddress is not null && !Uri.TryCreate(MetadataAddress, UriKind.Absolute, out _))
            return $"{nameof(MetadataAddress)} must be an absolute URL, or absent.";
        if (ClockSkew < TimeSpan.Zero)
            return $"{nameof(ClockSkew)} is zero or positive.";
        if (Decryption.FindError() is { } decryption)
            return $"{nameof(Decryption)}: {decryption}";
        return null;
    }
}

/// <summary>Registers the validation of the bearer tokens the issuer issued, on a resource server.</summary>
public static class BearerServiceCollectionExtensions
{
    /// <summary>
    /// Registers the JWT bearer authentication of the tokens the issuer issued, as the default scheme of the host,
    /// its options bound from <paramref name="sectionName"/> and validated at startup: the issuer as authority,
    /// the audiences of this host, the claims kept as the token names them (<c>sub</c>, <c>scope</c>, not their
    /// WS-Federation renames), the scopes split into one <c>scope</c> claim each. A host that authenticates with
    /// several schemes — the cookie of the accounts beside the bearer — chooses between them itself, with a
    /// policy scheme, after this call.
    /// </summary>
    public static IServiceCollection AddStellaegisBearer(this IServiceCollection services, IConfiguration configuration, string sectionName = IssuerBearerOptions.SectionName)
    {
        Guard.NotNull(configuration);
        Guard.NotWhiteSpace(sectionName);
        var options = new IssuerBearerOptions();
        configuration.GetSection(sectionName).Bind(options);
        services.AddStellaegisOptions<IssuerBearerOptions>(configuration, sectionName);
        return services.AddBearer(options);
    }

    /// <summary>
    /// Registers the bearer authentication as <see cref="AddStellaegisBearer(IServiceCollection, IConfiguration, string)"/>
    /// does, its options configured in code.
    /// </summary>
    public static IServiceCollection AddStellaegisBearer(this IServiceCollection services, Action<IssuerBearerOptions> configure)
    {
        Guard.NotNull(configure);
        var options = new IssuerBearerOptions();
        configure(options);
        services.AddStellaegisOptions(configure);
        return services.AddBearer(options);
    }

    private static IServiceCollection AddBearer(this IServiceCollection services, IssuerBearerOptions options)
    {
        Guard.NotNull(services);
        if (options.FindError() is { } error)
            throw new InvalidOperationException($"{nameof(IssuerBearerOptions)}: {error}");

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(jwt =>
            {
                jwt.Authority = options.Authority;
                jwt.RequireHttpsMetadata = options.RequireHttpsMetadata;
                jwt.MapInboundClaims = false;
                if (options.MetadataAddress is not null)
                    jwt.MetadataAddress = options.MetadataAddress;
                jwt.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidAudiences = options.Audiences,
                    ValidateAudience = true,
                    ValidateIssuer = true,
                    ValidateLifetime = true,
                    ClockSkew = options.ClockSkew,
                    TokenDecryptionKey = options.Decryption.IsSet ? new X509SecurityKey(options.Decryption.Load()) : null,
                };
                jwt.Events = new JwtBearerEvents { OnTokenValidated = SplitScopes };
            });
        services.AddAuthorization();
        return services;
    }

    /// <summary>The issuer writes the scopes as one space-separated <c>scope</c> claim; a policy reads one claim per scope.</summary>
    private static Task SplitScopes(TokenValidatedContext context)
    {
        if (context.Principal?.Identity is ClaimsIdentity identity && identity.FindFirst("scope") is { } scope && scope.Value.Contains(' '))
        {
            identity.RemoveClaim(scope);
            foreach (var value in scope.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                identity.AddClaim(new Claim("scope", value));
        }
        return Task.CompletedTask;
    }
}
