using System.Buffers.Text;
using System.Security.Cryptography;
using OpenIddict.Abstractions;
using Stellaegis.Primitives;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Stellaegis.Issuer;

/// <summary>A client the issuer provisioned, and its secret — shown once, never read back.</summary>
/// <param name="ClientId">The id of the client.</param>
/// <param name="Secret">Its secret, as the caller must keep it.</param>
public sealed record ProvisionedClient(string ClientId, string Secret);

/// <summary>
/// Gives a module its credentials to speak as itself: a confidential client with the <c>client_credentials</c>
/// grant, whose id is the module's name, and the scope of the same name whose resource is the module — a scope is
/// the name of a module, and its audience the same value. The installation calls it when it declares a module's
/// API; in the SaaS, the tenancy does. Registry never does: what a module is belongs to Registry, its credentials to
/// the issuer. The HTTP form is in <c>Stellaegis.Issuer.Client</c>.
/// </summary>
public interface IOidcClientProvisioner
{
    /// <summary>
    /// Creates the scope and the confidential client of <paramref name="moduleName"/>, and returns the secret, once.
    /// <see cref="IssuerErrors.ClientExists"/> when the client exists; the scope is created when missing.
    /// </summary>
    Task<Result<ProvisionedClient>> ProvisionModuleClientAsync(string moduleName, CancellationToken cancellationToken = default);

    /// <summary>Replaces the secret of the client <paramref name="clientId"/> and returns the new one, once.</summary>
    Task<Result<ProvisionedClient>> RotateSecretAsync(string clientId, CancellationToken cancellationToken = default);

    /// <summary>Removes the client of <paramref name="moduleName"/> and its scope; nothing to do when neither exists.</summary>
    Task DeprovisionModuleClientAsync(string moduleName, CancellationToken cancellationToken = default);
}

internal sealed class OpenIddictClientProvisioner(IOpenIddictApplicationManager applications, IOpenIddictScopeManager scopes) : IOidcClientProvisioner
{
    public async Task<Result<ProvisionedClient>> ProvisionModuleClientAsync(string moduleName, CancellationToken cancellationToken = default)
    {
        if (!NameRules.IsModuleName(moduleName))
            return Result.Failure<ProvisionedClient>(IssuerErrors.ClientInvalid($"'{moduleName}' is not the name of a module: {NameRules.ModuleNameRule}."));
        if (await applications.FindByClientIdAsync(moduleName, cancellationToken).ConfigureAwait(false) is not null)
            return Result.Failure<ProvisionedClient>(IssuerErrors.ClientExists);

        if (await scopes.FindByNameAsync(moduleName, cancellationToken).ConfigureAwait(false) is null)
        {
            var scope = new OpenIddictScopeDescriptor { Name = moduleName, DisplayName = moduleName };
            scope.Resources.Add(moduleName);
            await scopes.CreateAsync(scope, cancellationToken).ConfigureAwait(false);
        }

        var secret = NewSecret();
        var client = new OpenIddictApplicationDescriptor
        {
            ClientId = moduleName,
            ClientSecret = secret,
            ClientType = ClientTypes.Confidential,
            DisplayName = $"{moduleName} (module)",
        };
        client.Permissions.Add(Permissions.Endpoints.Token);
        client.Permissions.Add(Permissions.GrantTypes.ClientCredentials);
        client.Permissions.Add(Permissions.Prefixes.Scope + moduleName);
        await applications.CreateAsync(client, cancellationToken).ConfigureAwait(false);
        return Result.Success(new ProvisionedClient(moduleName, secret));
    }

    public async Task<Result<ProvisionedClient>> RotateSecretAsync(string clientId, CancellationToken cancellationToken = default)
    {
        Guard.NotWhiteSpace(clientId);
        var application = await applications.FindByClientIdAsync(clientId, cancellationToken).ConfigureAwait(false);
        if (application is null)
            return Result.Failure<ProvisionedClient>(IssuerErrors.ClientNotFound);
        if (await applications.GetClientTypeAsync(application, cancellationToken).ConfigureAwait(false) != ClientTypes.Confidential)
            return Result.Failure<ProvisionedClient>(IssuerErrors.ClientInvalid("A public client has no secret to rotate."));

        var descriptor = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(descriptor, application, cancellationToken).ConfigureAwait(false);
        var secret = NewSecret();
        descriptor.ClientSecret = secret;
        await applications.UpdateAsync(application, descriptor, cancellationToken).ConfigureAwait(false);
        return Result.Success(new ProvisionedClient(clientId, secret));
    }

    public async Task DeprovisionModuleClientAsync(string moduleName, CancellationToken cancellationToken = default)
    {
        Guard.NotWhiteSpace(moduleName);
        if (await applications.FindByClientIdAsync(moduleName, cancellationToken).ConfigureAwait(false) is { } application)
            await applications.DeleteAsync(application, cancellationToken).ConfigureAwait(false);
        if (await scopes.FindByNameAsync(moduleName, cancellationToken).ConfigureAwait(false) is { } scope)
            await scopes.DeleteAsync(scope, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>A secret of 256 random bits, in base64url.</summary>
    internal static string NewSecret() => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));
}
