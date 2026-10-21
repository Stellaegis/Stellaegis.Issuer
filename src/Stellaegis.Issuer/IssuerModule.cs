using Microsoft.Extensions.DependencyInjection;
using Stellaegis.Primitives;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Issuer;

/// <summary>
/// The identity of the issuer module, <c>issuer</c>: what its routes belong to, and what the application declares
/// it as. The module issues and revokes tokens for a user the host has authenticated, and holds the clients and
/// the scopes; it knows no account. It has no compartments — one issuer serves the whole application —, so its
/// routes read no request context.
/// </summary>
public sealed class IssuerModule : IStellaegisModule
{
    /// <inheritdoc/>
    public static string Name => "issuer";

    /// <summary>
    /// What the module declares to the application: no compartments, and the seven operations of its
    /// administration. The protocol routes under <c>/connect</c> carry no operation: a client calls them with its
    /// own credentials, the person with the host's authentication.
    /// </summary>
    public static ModuleDeclaration Declaration { get; } = ModuleDeclaration.WithoutCompartments<IssuerModule>()
        .WithOperations(IssuerOperations.All);
}

/// <summary>The operations of the issuer module, which its administration routes are labelled with.</summary>
public static class IssuerOperations
{
    /// <summary>Listing and reading the clients, <c>clients.read</c>.</summary>
    public static readonly Operation ClientsRead = new("clients", "read", OperationKind.Read);

    /// <summary>Creating a client, changing it, rotating its secret, <c>clients.write</c>.</summary>
    public static readonly Operation ClientsWrite = new("clients", "write", OperationKind.Write);

    /// <summary>Deleting a client, <c>clients.delete</c>.</summary>
    public static readonly Operation ClientsDelete = new("clients", "delete", OperationKind.Delete);

    /// <summary>Listing and reading the scopes, <c>scopes.read</c>.</summary>
    public static readonly Operation ScopesRead = new("scopes", "read", OperationKind.Read);

    /// <summary>Creating or changing a scope, <c>scopes.write</c>.</summary>
    public static readonly Operation ScopesWrite = new("scopes", "write", OperationKind.Write);

    /// <summary>Deleting a scope, <c>scopes.delete</c>.</summary>
    public static readonly Operation ScopesDelete = new("scopes", "delete", OperationKind.Delete);

    /// <summary>Revoking tokens — a token, a session, everything a subject holds —, and reading the revoked ones, <c>tokens.revoke</c>.</summary>
    public static readonly Operation TokensRevoke = new("tokens", "revoke", OperationKind.Delete);

    /// <summary>Every operation of the module.</summary>
    public static IReadOnlyList<Operation> All { get; } = [ClientsRead, ClientsWrite, ClientsDelete, ScopesRead, ScopesWrite, ScopesDelete, TokensRevoke];
}

/// <summary>Registers the issuer module itself.</summary>
public static class IssuerModuleServiceCollectionExtensions
{
    /// <summary>
    /// Declares the issuer module to the application (<see cref="IssuerModule.Declaration"/>). The issuer's
    /// registration calls it; calling it again registers nothing more.
    /// </summary>
    public static IServiceCollection AddStellaegisIssuerModule(this IServiceCollection services)
    {
        Guard.NotNull(services);
        if (services.Any(descriptor => descriptor.ServiceType == typeof(IssuerModuleRegistered)))
            return services;
        services.AddSingleton(IssuerModuleRegistered.Instance);
        return services.AddStellaegisModule(IssuerModule.Declaration);
    }

    private sealed class IssuerModuleRegistered
    {
        public static readonly IssuerModuleRegistered Instance = new();
    }
}
