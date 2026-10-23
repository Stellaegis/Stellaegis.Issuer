using Stellaegis.Issuer.Client;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Issuer;

/// <summary>
/// The options of the issuer, bound from <see cref="SectionName"/> or configured in code, and validated when the
/// host starts. What is secret or specific to an environment — a client's secret, its redirect URIs, the
/// certificates — is here; what a client is — its kind, its scopes — is declared by the installation through
/// <see cref="IssuerCatalog"/>.
/// <code>
/// Stellaegis:Issuer:Issuer = https://id.acme.example
/// Stellaegis:Issuer:AccessTokenLifetime = 00:10:00
/// Stellaegis:Issuer:Certificates:Signing:Path = /etc/stellaegis/signing.pfx
/// Stellaegis:Issuer:Certificates:Signing:Password = …                     (from a secret store)
/// Stellaegis:Issuer:Clients:craftnorma:RedirectUris:0 = http://127.0.0.1:7890/
/// Stellaegis:Issuer:Clients:documents:Secret = …                           (from a secret store)
/// </code>
/// </summary>
public sealed class IssuerOptions : IValidatableOptions
{
    /// <summary>The configuration section of the issuer.</summary>
    public const string SectionName = "Stellaegis:Issuer";

    /// <summary>
    /// The issuer URI advertised by the discovery document and carried by every token, an absolute http or https
    /// URL; derived from the request when not set. Set it whenever the issuer is reached under several addresses.
    /// </summary>
    public string? Issuer { get; set; }

    /// <summary>How long an access token lives. Ten minutes unless set.</summary>
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>How long an identity token lives. Ten minutes unless set.</summary>
    public TimeSpan IdentityTokenLifetime { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>How long an authorization code lives, between the redirect and its exchange. Five minutes unless set.</summary>
    public TimeSpan AuthorizationCodeLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>How long a refresh token lives. Thirty days unless set.</summary>
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(30);

    /// <summary>
    /// Whether access tokens are encrypted (JWE) as well as signed, so that nothing but a resource server holding
    /// the encryption key reads them. Yes unless set; a signed-only token (JWS) lets any resource server validate
    /// it with the public keys of the discovery document.
    /// </summary>
    public bool EncryptAccessTokens { get; set; } = true;

    /// <summary>
    /// Whether the protocol routes require HTTPS. Yes unless set; a development host behind plain HTTP sets it
    /// to <see langword="false"/>, and a production host never does.
    /// </summary>
    public bool RequireHttps { get; set; } = true;

    /// <summary>
    /// The authentication scheme the authorization route challenges and reads a person from — the cookie of
    /// Stellaegis.Identity, Negotiate, whatever the host authenticates with. The host's default scheme unless set.
    /// </summary>
    public string? AuthenticationScheme { get; set; }

    /// <summary>
    /// The name of a rate-limiting policy of the host to apply to the token route, which an attacker would hammer.
    /// None unless set: the issuer does not know what limiter the host has.
    /// </summary>
    public string? TokenRateLimitingPolicy { get; set; }

    /// <summary>
    /// The scopes the issuer knows besides those of the catalog: the standard <c>email</c> and <c>profile</c>
    /// unless set. <c>openid</c> and <c>offline_access</c> are always known.
    /// </summary>
    public string[] StandardScopes { get; set; } = ["email", "profile"];

    /// <summary>The certificates the tokens are signed and encrypted with.</summary>
    public IssuerCertificatesOptions Certificates { get; set; } = new();

    /// <summary>
    /// What an environment adds to a client the installation declared, by client id: its secret, its redirect
    /// URIs. <see cref="IssuerCatalog"/> overlays them on a definition that leaves them empty, and
    /// <see cref="IssuerCatalog.ApplyConfiguredClientsAsync"/> re-applies them to the clients already declared.
    /// </summary>
    public Dictionary<string, ConfiguredClientOptions> Clients { get; set; } = new(StringComparer.Ordinal);

    /// <inheritdoc/>
    public string? FindError()
    {
        if (Issuer is not null && (!Uri.TryCreate(Issuer, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)))
            return $"{nameof(Issuer)} must be an absolute http or https URL.";
        if (AccessTokenLifetime <= TimeSpan.Zero)
            return $"{nameof(AccessTokenLifetime)} must be positive.";
        if (IdentityTokenLifetime <= TimeSpan.Zero)
            return $"{nameof(IdentityTokenLifetime)} must be positive.";
        if (AuthorizationCodeLifetime <= TimeSpan.Zero)
            return $"{nameof(AuthorizationCodeLifetime)} must be positive.";
        if (RefreshTokenLifetime <= TimeSpan.Zero)
            return $"{nameof(RefreshTokenLifetime)} must be positive.";
        if (StandardScopes.Any(string.IsNullOrWhiteSpace))
            return $"{nameof(StandardScopes)} holds an empty scope.";
        if (Certificates.FindError() is { } certificates)
            return $"{nameof(Certificates)}: {certificates}";
        foreach (var (clientId, client) in Clients)
        {
            if (string.IsNullOrWhiteSpace(clientId))
                return $"{nameof(Clients)} holds an empty client id.";
            if (client.FindError() is { } error)
                return $"{nameof(Clients)}:{clientId}: {error}";
        }
        return null;
    }
}

/// <summary>
/// The certificates the tokens are signed and encrypted with. Outside development both are required: a signing
/// certificate, and an encryption certificate when <see cref="IssuerOptions.EncryptAccessTokens"/> holds. A
/// certificate comes from a PKCS #12 file and its password, or from the certificate store by its thumbprint.
/// </summary>
public sealed class IssuerCertificatesOptions : IValidatableOptions
{
    /// <summary>
    /// Whether to use the ephemeral development certificates OpenIddict generates, which every restart renews —
    /// every token issued before is then invalid. Accepted in the Development environment only. No unless set.
    /// </summary>
    public bool UseDevelopmentCertificates { get; set; }

    /// <summary>The certificate the tokens are signed with.</summary>
    public IssuerCertificateOptions Signing { get; set; } = new();

    /// <summary>The certificate the access tokens are encrypted with.</summary>
    public IssuerCertificateOptions Encryption { get; set; } = new();

    /// <inheritdoc/>
    /// <remarks>
    /// With the development certificates, <see cref="Signing"/> and <see cref="Encryption"/> are not loaded, and
    /// not checked: the placeholders of a development configuration — a password <c>CHANGE_ME</c> — stay harmless.
    /// </remarks>
    public string? FindError()
    {
        if (UseDevelopmentCertificates)
            return null;
        if (Signing.FindError() is { } signing)
            return $"{nameof(Signing)}: {signing}";
        if (Encryption.FindError() is { } encryption)
            return $"{nameof(Encryption)}: {encryption}";
        return null;
    }
}

/// <summary>What an environment adds to a client the installation declared.</summary>
public sealed class ConfiguredClientOptions : IValidatableOptions
{
    /// <summary>
    /// The secret of a confidential client, from a secret store. A public client has none; left empty, as an
    /// exhaustive appsettings.json shows it, it is absent.
    /// </summary>
    public string? Secret { get; set; }

    /// <summary>The secret, or <see langword="null"/> when it is left empty.</summary>
    internal string? SecretOrNull => string.IsNullOrWhiteSpace(Secret) ? null : Secret;

    /// <summary>The redirect URIs of a public client, absolute, which depend on where the client runs.</summary>
    public string[] RedirectUris { get; set; } = [];

    /// <summary>The URIs a public client may be sent back to after a logout, absolute.</summary>
    public string[] PostLogoutRedirectUris { get; set; } = [];

    /// <inheritdoc/>
    public string? FindError()
    {
        foreach (var uri in RedirectUris.Concat(PostLogoutRedirectUris))
        {
            if (!Uri.TryCreate(uri, UriKind.Absolute, out _))
                return $"'{uri}' is not an absolute URI.";
        }
        return null;
    }
}
