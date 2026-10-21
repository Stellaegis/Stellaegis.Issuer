using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using Stellaegis.Primitives;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Stellaegis.Issuer;

/// <summary>What a client is: public, a browser or a native application that holds no secret and proves itself by PKCE; or confidential, a service that holds a secret.</summary>
public enum ClientKind
{
    /// <summary>A browser or a native application: authorization code with PKCE, refresh tokens, no secret.</summary>
    Public,

    /// <summary>A service: client credentials, a secret.</summary>
    Confidential,
}

/// <summary>A client as the catalog shows it: nothing secret.</summary>
/// <param name="ClientId">Its id.</param>
/// <param name="DisplayName">Its display name.</param>
/// <param name="Kind">Whether it is public or confidential.</param>
/// <param name="Scopes">The scopes it may request, besides <c>openid</c> and <c>offline_access</c>.</param>
/// <param name="RedirectUris">Where a public client is sent back with its code.</param>
/// <param name="PostLogoutRedirectUris">Where a public client is sent back after a logout.</param>
public sealed record OidcClient(
    string ClientId,
    string DisplayName,
    ClientKind Kind,
    IReadOnlyList<string> Scopes,
    IReadOnlyList<string> RedirectUris,
    IReadOnlyList<string> PostLogoutRedirectUris);

/// <summary>
/// A client to create or to change. What is secret or specific to the environment — the secret, the redirect
/// URIs — may be left empty: the catalog then takes it from <see cref="IssuerOptions.Clients"/>, under the client
/// id, where the installation's declaration meets the environment's configuration.
/// </summary>
/// <param name="ClientId">Its id: 1 to 100 letters, digits, <c>_</c>, <c>-</c> or <c>.</c>.</param>
/// <param name="DisplayName">Its display name; the id unless given.</param>
/// <param name="Kind">Whether it is public or confidential.</param>
/// <param name="Scopes">The scopes it may request, besides <c>openid</c> and <c>offline_access</c>.</param>
/// <param name="RedirectUris">Where a public client is sent back with its code; absolute URIs.</param>
/// <param name="PostLogoutRedirectUris">Where a public client is sent back after a logout; absolute URIs.</param>
/// <param name="Secret">The secret of a confidential client; generated and returned once when left empty.</param>
public sealed record ClientDefinition(
    string ClientId,
    string? DisplayName = null,
    ClientKind Kind = ClientKind.Public,
    IReadOnlyList<string>? Scopes = null,
    IReadOnlyList<string>? RedirectUris = null,
    IReadOnlyList<string>? PostLogoutRedirectUris = null,
    string? Secret = null);

/// <summary>A client just created or changed, and its secret when one was generated — shown once, never read back.</summary>
/// <param name="Client">The client.</param>
/// <param name="Secret">The secret generated, or <see langword="null"/> when the client is public or the secret was given.</param>
public sealed record ClientSaved(OidcClient Client, string? Secret);

/// <summary>A scope as the catalog shows it.</summary>
/// <param name="Name">Its name, which is the name of a module.</param>
/// <param name="DisplayName">Its display name.</param>
/// <param name="Description">What it gives access to, for a consent screen.</param>
/// <param name="Resources">The audiences a token carrying it addresses — the module's name, by the family's rule.</param>
public sealed record OidcScope(string Name, string DisplayName, string? Description, IReadOnlyList<string> Resources);

/// <summary>A scope to create or to change.</summary>
/// <param name="Name">Its name: the name of a module, 3 to 63 lowercase letters and digits.</param>
/// <param name="DisplayName">Its display name; the name unless given.</param>
/// <param name="Description">What it gives access to.</param>
/// <param name="Resources">Its audiences; the name alone unless given.</param>
public sealed record ScopeDefinition(string Name, string? DisplayName = null, string? Description = null, IReadOnlyList<string>? Resources = null);

/// <summary>
/// The clients and the scopes of the issuer, as the installation declares them and the administration reads and
/// changes them. A client's secret is never read back: it is given at creation, or regenerated. The catalog holds
/// no client of its own — the framework's eleven system clients are not here —: what exists is what was declared.
/// </summary>
public sealed class IssuerCatalog(IOpenIddictApplicationManager applications, IOpenIddictScopeManager scopes, IOptions<IssuerOptions> options)
{
    private static readonly string[] AlwaysAllowedScopes = [Scopes.OpenId, Scopes.OfflineAccess];

    /// <summary>Every client, by id.</summary>
    public async Task<IReadOnlyList<OidcClient>> ListClientsAsync(CancellationToken cancellationToken = default)
    {
        var list = new List<OidcClient>();
        await foreach (var application in applications.ListAsync(cancellationToken: cancellationToken).ConfigureAwait(false))
            list.Add(await ToClientAsync(application, cancellationToken).ConfigureAwait(false));
        return list.OrderBy(client => client.ClientId, StringComparer.Ordinal).ToList();
    }

    /// <summary>One client, or <see cref="IssuerErrors.ClientNotFound"/>.</summary>
    public async Task<Result<OidcClient>> GetClientAsync(string clientId, CancellationToken cancellationToken = default)
    {
        Guard.NotWhiteSpace(clientId);
        var application = await applications.FindByClientIdAsync(clientId, cancellationToken).ConfigureAwait(false);
        return application is null
            ? Result.Failure<OidcClient>(IssuerErrors.ClientNotFound)
            : Result.Success(await ToClientAsync(application, cancellationToken).ConfigureAwait(false));
    }

    /// <summary>
    /// Creates a client. A public client gets the authorization code flow with PKCE and refresh tokens; a
    /// confidential one the client credentials, and a secret generated when the definition and the configuration
    /// give none. <see cref="IssuerErrors.ClientExists"/> when the id is taken, <see cref="IssuerErrors.ClientInvalid"/>
    /// when the definition does not hold.
    /// </summary>
    public async Task<Result<ClientSaved>> CreateClientAsync(ClientDefinition definition, CancellationToken cancellationToken = default)
    {
        Guard.NotNull(definition);
        if (Validate(definition) is { } invalid)
            return Result.Failure<ClientSaved>(invalid);
        if (await applications.FindByClientIdAsync(definition.ClientId, cancellationToken).ConfigureAwait(false) is not null)
            return Result.Failure<ClientSaved>(IssuerErrors.ClientExists);

        var (descriptor, generated) = Describe(definition);
        var application = await applications.CreateAsync(descriptor, cancellationToken).ConfigureAwait(false);
        return Result.Success(new ClientSaved(await ToClientAsync(application, cancellationToken).ConfigureAwait(false), generated));
    }

    /// <summary>
    /// Replaces a client's definition. The secret of a confidential client is kept when the definition and the
    /// configuration give none. <see cref="IssuerErrors.ClientNotFound"/> when no client has that id.
    /// </summary>
    public async Task<Result<ClientSaved>> UpdateClientAsync(ClientDefinition definition, CancellationToken cancellationToken = default)
    {
        Guard.NotNull(definition);
        if (Validate(definition) is { } invalid)
            return Result.Failure<ClientSaved>(invalid);
        var application = await applications.FindByClientIdAsync(definition.ClientId, cancellationToken).ConfigureAwait(false);
        if (application is null)
            return Result.Failure<ClientSaved>(IssuerErrors.ClientNotFound);

        var (descriptor, generated) = Describe(definition, keepSecret: true);
        if (descriptor.ClientType == ClientTypes.Confidential && descriptor.ClientSecret is null)
        {
            // The secret is kept: the descriptor carries the stored one, which the manager then leaves as it is.
            var current = new OpenIddictApplicationDescriptor();
            await applications.PopulateAsync(current, application, cancellationToken).ConfigureAwait(false);
            descriptor.ClientSecret = current.ClientSecret;
        }
        await applications.UpdateAsync(application, descriptor, cancellationToken).ConfigureAwait(false);
        return Result.Success(new ClientSaved(await ToClientAsync(application, cancellationToken).ConfigureAwait(false), generated));
    }

    /// <summary>Deletes a client, with its authorizations and tokens. <see cref="IssuerErrors.ClientNotFound"/> when no client has that id.</summary>
    public async Task<Result> DeleteClientAsync(string clientId, CancellationToken cancellationToken = default)
    {
        Guard.NotWhiteSpace(clientId);
        var application = await applications.FindByClientIdAsync(clientId, cancellationToken).ConfigureAwait(false);
        if (application is null)
            return Result.Failure(IssuerErrors.ClientNotFound);
        await applications.DeleteAsync(application, cancellationToken).ConfigureAwait(false);
        return Result.Success();
    }

    /// <summary>
    /// Re-applies what the environment configures of the clients already declared, <see cref="IssuerOptions.Clients"/>:
    /// the secret, the redirect URIs. What the installation calls after a configuration changed; a client the
    /// configuration names and the catalog does not hold is skipped. Returns the ids of the clients changed.
    /// </summary>
    public async Task<IReadOnlyList<string>> ApplyConfiguredClientsAsync(CancellationToken cancellationToken = default)
    {
        var changed = new List<string>();
        foreach (var (clientId, configured) in options.Value.Clients)
        {
            var application = await applications.FindByClientIdAsync(clientId, cancellationToken).ConfigureAwait(false);
            if (application is null)
                continue;
            var descriptor = new OpenIddictApplicationDescriptor();
            await applications.PopulateAsync(descriptor, application, cancellationToken).ConfigureAwait(false);
            if (descriptor.ClientType == ClientTypes.Confidential && configured.Secret is not null)
                descriptor.ClientSecret = configured.Secret;
            if (configured.RedirectUris.Length > 0)
            {
                descriptor.RedirectUris.Clear();
                foreach (var uri in configured.RedirectUris)
                    descriptor.RedirectUris.Add(new Uri(uri, UriKind.Absolute));
            }
            if (configured.PostLogoutRedirectUris.Length > 0)
            {
                descriptor.PostLogoutRedirectUris.Clear();
                foreach (var uri in configured.PostLogoutRedirectUris)
                    descriptor.PostLogoutRedirectUris.Add(new Uri(uri, UriKind.Absolute));
            }
            await applications.UpdateAsync(application, descriptor, cancellationToken).ConfigureAwait(false);
            changed.Add(clientId);
        }
        return changed;
    }

    /// <summary>Every scope, by name.</summary>
    public async Task<IReadOnlyList<OidcScope>> ListScopesAsync(CancellationToken cancellationToken = default)
    {
        var list = new List<OidcScope>();
        await foreach (var scope in scopes.ListAsync(cancellationToken: cancellationToken).ConfigureAwait(false))
            list.Add(await ToScopeAsync(scope, cancellationToken).ConfigureAwait(false));
        return list.OrderBy(scope => scope.Name, StringComparer.Ordinal).ToList();
    }

    /// <summary>One scope, or <see cref="IssuerErrors.ScopeNotFound"/>.</summary>
    public async Task<Result<OidcScope>> GetScopeAsync(string name, CancellationToken cancellationToken = default)
    {
        Guard.NotWhiteSpace(name);
        var scope = await scopes.FindByNameAsync(name, cancellationToken).ConfigureAwait(false);
        return scope is null
            ? Result.Failure<OidcScope>(IssuerErrors.ScopeNotFound)
            : Result.Success(await ToScopeAsync(scope, cancellationToken).ConfigureAwait(false));
    }

    /// <summary>Creates a scope. <see cref="IssuerErrors.ScopeExists"/> when the name is taken, <see cref="IssuerErrors.ScopeInvalid"/> when the definition does not hold.</summary>
    public async Task<Result<OidcScope>> CreateScopeAsync(ScopeDefinition definition, CancellationToken cancellationToken = default)
    {
        Guard.NotNull(definition);
        if (Validate(definition) is { } invalid)
            return Result.Failure<OidcScope>(invalid);
        if (await scopes.FindByNameAsync(definition.Name, cancellationToken).ConfigureAwait(false) is not null)
            return Result.Failure<OidcScope>(IssuerErrors.ScopeExists);
        var scope = await scopes.CreateAsync(Describe(definition), cancellationToken).ConfigureAwait(false);
        return Result.Success(await ToScopeAsync(scope, cancellationToken).ConfigureAwait(false));
    }

    /// <summary>Replaces a scope's definition. <see cref="IssuerErrors.ScopeNotFound"/> when no scope has that name.</summary>
    public async Task<Result<OidcScope>> UpdateScopeAsync(ScopeDefinition definition, CancellationToken cancellationToken = default)
    {
        Guard.NotNull(definition);
        if (Validate(definition) is { } invalid)
            return Result.Failure<OidcScope>(invalid);
        var scope = await scopes.FindByNameAsync(definition.Name, cancellationToken).ConfigureAwait(false);
        if (scope is null)
            return Result.Failure<OidcScope>(IssuerErrors.ScopeNotFound);
        await scopes.UpdateAsync(scope, Describe(definition), cancellationToken).ConfigureAwait(false);
        return Result.Success(await ToScopeAsync(scope, cancellationToken).ConfigureAwait(false));
    }

    /// <summary>Deletes a scope. <see cref="IssuerErrors.ScopeNotFound"/> when no scope has that name.</summary>
    public async Task<Result> DeleteScopeAsync(string name, CancellationToken cancellationToken = default)
    {
        Guard.NotWhiteSpace(name);
        var scope = await scopes.FindByNameAsync(name, cancellationToken).ConfigureAwait(false);
        if (scope is null)
            return Result.Failure(IssuerErrors.ScopeNotFound);
        await scopes.DeleteAsync(scope, cancellationToken).ConfigureAwait(false);
        return Result.Success();
    }

    private static Error? Validate(ClientDefinition definition)
    {
        if (string.IsNullOrWhiteSpace(definition.ClientId) || definition.ClientId.Length > 100 || !definition.ClientId.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.'))
            return IssuerErrors.ClientInvalid("A client id is 1 to 100 letters, digits, '_', '-' or '.'.");
        foreach (var scope in definition.Scopes ?? [])
        {
            if (string.IsNullOrWhiteSpace(scope) || scope.Any(char.IsWhiteSpace))
                return IssuerErrors.ClientInvalid($"'{scope}' is not a scope.");
        }
        foreach (var uri in (definition.RedirectUris ?? []).Concat(definition.PostLogoutRedirectUris ?? []))
        {
            if (!Uri.TryCreate(uri, UriKind.Absolute, out _))
                return IssuerErrors.ClientInvalid($"'{uri}' is not an absolute URI.");
        }
        if (definition.Kind == ClientKind.Public && definition.Secret is not null)
            return IssuerErrors.ClientInvalid("A public client holds no secret.");
        if (definition.Secret is not null && string.IsNullOrWhiteSpace(definition.Secret))
            return IssuerErrors.ClientInvalid("The secret is empty.");
        return null;
    }

    private static Error? Validate(ScopeDefinition definition)
    {
        if (!NameRules.IsModuleName(definition.Name))
            return IssuerErrors.ScopeInvalid($"A scope is the name of a module: {NameRules.ModuleNameRule}.");
        foreach (var resource in definition.Resources ?? [])
        {
            if (string.IsNullOrWhiteSpace(resource) || resource.Any(char.IsWhiteSpace))
                return IssuerErrors.ScopeInvalid($"'{resource}' is not a resource.");
        }
        return null;
    }

    /// <summary>The descriptor of a client, the environment's configuration overlaid where the definition is silent; and the secret generated, if one was.</summary>
    private (OpenIddictApplicationDescriptor Descriptor, string? Generated) Describe(ClientDefinition definition, bool keepSecret = false)
    {
        options.Value.Clients.TryGetValue(definition.ClientId, out var configured);
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = definition.ClientId,
            DisplayName = string.IsNullOrWhiteSpace(definition.DisplayName) ? definition.ClientId : definition.DisplayName,
            ClientType = definition.Kind == ClientKind.Public ? ClientTypes.Public : ClientTypes.Confidential,
            ConsentType = ConsentTypes.Implicit,
        };
        string? generated = null;
        if (definition.Kind == ClientKind.Confidential)
        {
            descriptor.ClientSecret = definition.Secret ?? configured?.Secret;
            if (descriptor.ClientSecret is null && !keepSecret)
                descriptor.ClientSecret = generated = OpenIddictClientProvisioner.NewSecret();
            descriptor.Permissions.Add(Permissions.Endpoints.Token);
            descriptor.Permissions.Add(Permissions.GrantTypes.ClientCredentials);
        }
        else
        {
            descriptor.Permissions.Add(Permissions.Endpoints.Authorization);
            descriptor.Permissions.Add(Permissions.Endpoints.Token);
            descriptor.Permissions.Add(Permissions.Endpoints.EndSession);
            descriptor.Permissions.Add(Permissions.GrantTypes.AuthorizationCode);
            descriptor.Permissions.Add(Permissions.GrantTypes.RefreshToken);
            descriptor.Permissions.Add(Permissions.ResponseTypes.Code);
            descriptor.Requirements.Add(Requirements.Features.ProofKeyForCodeExchange);
            var redirects = definition.RedirectUris is { Count: > 0 } given ? given : configured?.RedirectUris ?? [];
            foreach (var uri in redirects)
                descriptor.RedirectUris.Add(new Uri(uri, UriKind.Absolute));
            var postLogout = definition.PostLogoutRedirectUris is { Count: > 0 } givenLogout ? givenLogout : configured?.PostLogoutRedirectUris ?? [];
            foreach (var uri in postLogout)
                descriptor.PostLogoutRedirectUris.Add(new Uri(uri, UriKind.Absolute));
        }
        foreach (var scope in (definition.Scopes ?? []).Where(scope => !AlwaysAllowedScopes.Contains(scope, StringComparer.Ordinal)))
            descriptor.Permissions.Add(Permissions.Prefixes.Scope + scope);
        return (descriptor, generated);
    }

    private static OpenIddictScopeDescriptor Describe(ScopeDefinition definition)
    {
        var descriptor = new OpenIddictScopeDescriptor
        {
            Name = definition.Name,
            DisplayName = string.IsNullOrWhiteSpace(definition.DisplayName) ? definition.Name : definition.DisplayName,
            Description = definition.Description,
        };
        foreach (var resource in definition.Resources is { Count: > 0 } given ? given : [definition.Name])
            descriptor.Resources.Add(resource);
        return descriptor;
    }

    private async Task<OidcClient> ToClientAsync(object application, CancellationToken cancellationToken)
    {
        var permissions = await applications.GetPermissionsAsync(application, cancellationToken).ConfigureAwait(false);
        return new OidcClient(
            (await applications.GetClientIdAsync(application, cancellationToken).ConfigureAwait(false))!,
            await applications.GetDisplayNameAsync(application, cancellationToken).ConfigureAwait(false) ?? "",
            await applications.GetClientTypeAsync(application, cancellationToken).ConfigureAwait(false) == ClientTypes.Public ? ClientKind.Public : ClientKind.Confidential,
            permissions.Where(permission => permission.StartsWith(Permissions.Prefixes.Scope, StringComparison.Ordinal)).Select(permission => permission[Permissions.Prefixes.Scope.Length..]).Order(StringComparer.Ordinal).ToList(),
            (await applications.GetRedirectUrisAsync(application, cancellationToken).ConfigureAwait(false)).ToList(),
            (await applications.GetPostLogoutRedirectUrisAsync(application, cancellationToken).ConfigureAwait(false)).ToList());
    }

    private async Task<OidcScope> ToScopeAsync(object scope, CancellationToken cancellationToken)
        => new(
            (await scopes.GetNameAsync(scope, cancellationToken).ConfigureAwait(false))!,
            await scopes.GetDisplayNameAsync(scope, cancellationToken).ConfigureAwait(false) ?? "",
            await scopes.GetDescriptionAsync(scope, cancellationToken).ConfigureAwait(false),
            (await scopes.GetResourcesAsync(scope, cancellationToken).ConfigureAwait(false)).ToList());
}
