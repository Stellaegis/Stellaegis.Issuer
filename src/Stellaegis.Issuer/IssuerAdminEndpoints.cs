using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Stellaegis.Issuer.Client;
using Stellaegis.Primitives;
using Stellaegis.Primitives.AspNetCore;

namespace Stellaegis.Issuer;

/// <summary>
/// Maps the administration routes of the issuer: the clients and the scopes through <see cref="IssuerCatalog"/>,
/// the credentials of a module through <see cref="IOidcClientProvisioner"/>, the revocation through
/// <see cref="ITokenRevoker"/>, and the revoked tokens a resource server apart reads through
/// <c>Stellaegis.Issuer.Client</c>.
/// </summary>
/// <remarks>
/// <para>
/// The module has no compartments: its routes read no request context. A client or a scope is nobody's resource
/// — no compartment, no owner —, so the routes declare they load none: the operation each is labelled with is the
/// whole decision, and the host declares who may call it, by operation or on the group. The startup check of
/// <c>Stellaegis.Primitives.AspNetCore</c> refuses a route left without authorization.
/// </para>
/// <list type="bullet">
///   <item><c>GET issuer/clients</c>, <c>GET issuer/clients/{clientId}</c> — <c>clients.read</c></item>
///   <item><c>POST issuer/clients</c> — create, 201 with the client and its secret when one was generated; <c>PUT issuer/clients/{clientId}</c> — replace; <c>POST issuer/clients/{clientId}/rotate-secret</c> — a new secret, shown once; <c>clients.write</c></item>
///   <item><c>DELETE issuer/clients/{clientId}</c> — <c>clients.delete</c></item>
///   <item><c>GET issuer/scopes</c>, <c>GET issuer/scopes/{name}</c> — <c>scopes.read</c>; <c>POST issuer/scopes</c>, <c>PUT issuer/scopes/{name}</c> — <c>scopes.write</c>; <c>DELETE issuer/scopes/{name}</c> — <c>scopes.delete</c></item>
///   <item><c>POST issuer/apis/{moduleName}</c> — the credentials of a module, 201 with the secret shown once; <c>POST issuer/apis/{moduleName}/rotate-secret</c> — <c>clients.write</c>; <c>DELETE issuer/apis/{moduleName}</c> — <c>clients.delete</c>. Provisioning a module is writing a client: no operation of its own</item>
///   <item><c>POST issuer/subjects/{subject}/revoke</c>, <c>POST issuer/authorizations/{authorizationId}/revoke</c>, <c>POST issuer/tokens/{tokenId}/revoke</c>, and <c>GET issuer/security/revoked-tokens</c> — <c>tokens.revoke</c></item>
/// </list>
/// <para>A secret is returned once, at creation or rotation, and never read back. The routes carry no name, so the module can be mapped several times in one host.</para>
/// </remarks>
/// <example>
/// <code>
/// builder.Services.AddStellaegisIssuerPostgreSQL(builder.Configuration);
/// builder.Services.AddStellaegisIssuerAdministration();
///
/// var app = builder.Build();
/// app.UseAuthentication();
/// app.UseAuthorization();
/// app.MapGroup("/api/admin").MapIssuerAdminEndpoints().RequireAuthorizationPerOperation(op => op.ToString());
/// </code>
/// </example>
public static class IssuerAdminEndpoints
{
    /// <summary>
    /// Registers the startup check of the routes, which <see cref="MapIssuerAdminEndpoints"/> needs: a module
    /// without compartments registers it from its own registration, since no request context does. Harmless when
    /// something else registered it.
    /// </summary>
    public static IServiceCollection AddStellaegisIssuerAdministration(this IServiceCollection services)
    {
        Guard.NotNull(services);
        return services.AddStellaegisStartupCheck();
    }

    /// <summary>
    /// Maps the administration routes of the issuer, relative to <paramref name="endpoints"/>, under <c>issuer</c>.
    /// The host declares who may call them on the returned group.
    /// </summary>
    /// <param name="endpoints">The builder to map the routes on — the application, or a route group.</param>
    /// <returns>The group holding the routes, for the host's authorization and further conventions.</returns>
    public static RouteGroupBuilder MapIssuerAdminEndpoints(this IEndpointRouteBuilder endpoints)
    {
        Guard.NotNull(endpoints);
        var group = endpoints.MapGroup("issuer")
            .BelongsTo<IssuerModule>()
            .LoadsNoResource()
            .AddErrorTranslation();

        var clients = group.MapGroup("/clients");

        clients.MapGet("/", async (IssuerCatalog catalog, CancellationToken ct) => Results.Ok(await catalog.ListClientsAsync(ct)))
            .WithMetadata(IssuerOperations.ClientsRead)
            .Produces<IReadOnlyList<OidcClient>>(StatusCodes.Status200OK);

        clients.MapGet("/{clientId}", async (string clientId, IssuerCatalog catalog, CancellationToken ct) =>
                (await catalog.GetClientAsync(clientId, ct)).ToHttpResult())
            .WithMetadata(IssuerOperations.ClientsRead)
            .Produces<OidcClient>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status404NotFound);

        clients.MapPost("/", async (ClientDefinition definition, IssuerCatalog catalog, CancellationToken ct) =>
            {
                if (definition is null)
                    return Result.Failure(IssuerErrors.ClientInvalid("A client definition is required.")).ToHttpResult();
                var created = await catalog.CreateClientAsync(definition, ct);
                return created.IsSuccess ? Results.Created((string?)null, created.Value) : created.ToHttpResult();
            })
            .WithMetadata(IssuerOperations.ClientsWrite)
            .Produces<ClientSaved>(StatusCodes.Status201Created)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status409Conflict);

        clients.MapPut("/{clientId}", async (string clientId, ClientDefinition definition, IssuerCatalog catalog, CancellationToken ct) =>
            {
                if (definition is null)
                    return Result.Failure(IssuerErrors.ClientInvalid("A client definition is required.")).ToHttpResult();
                if (!string.IsNullOrEmpty(definition.ClientId) && !string.Equals(definition.ClientId, clientId, StringComparison.Ordinal))
                    return Result.Failure(IssuerErrors.ClientInvalid("The client id of the route and of the definition differ.")).ToHttpResult();
                return (await catalog.UpdateClientAsync(definition with { ClientId = clientId }, ct)).ToHttpResult();
            })
            .WithMetadata(IssuerOperations.ClientsWrite)
            .Produces<ClientSaved>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status404NotFound);

        clients.MapPost("/{clientId}/rotate-secret", async (string clientId, IOidcClientProvisioner provisioner, CancellationToken ct) =>
                (await provisioner.RotateSecretAsync(clientId, ct)).ToHttpResult())
            .WithMetadata(IssuerOperations.ClientsWrite)
            .Produces<ProvisionedClient>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status404NotFound);

        clients.MapDelete("/{clientId}", async (string clientId, IssuerCatalog catalog, CancellationToken ct) =>
                (await catalog.DeleteClientAsync(clientId, ct)).ToHttpResult())
            .WithMetadata(IssuerOperations.ClientsDelete)
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status404NotFound);

        var scopes = group.MapGroup("/scopes");

        scopes.MapGet("/", async (IssuerCatalog catalog, CancellationToken ct) => Results.Ok(await catalog.ListScopesAsync(ct)))
            .WithMetadata(IssuerOperations.ScopesRead)
            .Produces<IReadOnlyList<OidcScope>>(StatusCodes.Status200OK);

        scopes.MapGet("/{name}", async (string name, IssuerCatalog catalog, CancellationToken ct) =>
                (await catalog.GetScopeAsync(name, ct)).ToHttpResult())
            .WithMetadata(IssuerOperations.ScopesRead)
            .Produces<OidcScope>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status404NotFound);

        scopes.MapPost("/", async (ScopeDefinition definition, IssuerCatalog catalog, CancellationToken ct) =>
            {
                if (definition is null)
                    return Result.Failure(IssuerErrors.ScopeInvalid("A scope definition is required.")).ToHttpResult();
                var created = await catalog.CreateScopeAsync(definition, ct);
                return created.IsSuccess ? Results.Created((string?)null, created.Value) : created.ToHttpResult();
            })
            .WithMetadata(IssuerOperations.ScopesWrite)
            .Produces<OidcScope>(StatusCodes.Status201Created)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status409Conflict);

        scopes.MapPut("/{name}", async (string name, ScopeDefinition definition, IssuerCatalog catalog, CancellationToken ct) =>
            {
                if (definition is null)
                    return Result.Failure(IssuerErrors.ScopeInvalid("A scope definition is required.")).ToHttpResult();
                if (!string.IsNullOrEmpty(definition.Name) && !string.Equals(definition.Name, name, StringComparison.Ordinal))
                    return Result.Failure(IssuerErrors.ScopeInvalid("The scope name of the route and of the definition differ.")).ToHttpResult();
                return (await catalog.UpdateScopeAsync(definition with { Name = name }, ct)).ToHttpResult();
            })
            .WithMetadata(IssuerOperations.ScopesWrite)
            .Produces<OidcScope>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status404NotFound);

        scopes.MapDelete("/{name}", async (string name, IssuerCatalog catalog, CancellationToken ct) =>
                (await catalog.DeleteScopeAsync(name, ct)).ToHttpResult())
            .WithMetadata(IssuerOperations.ScopesDelete)
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status404NotFound);

        var apis = group.MapGroup("/apis");

        apis.MapPost("/{moduleName}", async (string moduleName, IOidcClientProvisioner provisioner, CancellationToken ct) =>
            {
                var provisioned = await provisioner.ProvisionModuleClientAsync(moduleName, ct);
                return provisioned.IsSuccess ? Results.Created((string?)null, provisioned.Value) : provisioned.ToHttpResult();
            })
            .WithMetadata(IssuerOperations.ClientsWrite)
            .Produces<ProvisionedClient>(StatusCodes.Status201Created)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status409Conflict);

        apis.MapPost("/{moduleName}/rotate-secret", async (string moduleName, IOidcClientProvisioner provisioner, CancellationToken ct) =>
                (await provisioner.RotateSecretAsync(moduleName, ct)).ToHttpResult())
            .WithMetadata(IssuerOperations.ClientsWrite)
            .Produces<ProvisionedClient>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status404NotFound);

        apis.MapDelete("/{moduleName}", async (string moduleName, IOidcClientProvisioner provisioner, CancellationToken ct) =>
            {
                await provisioner.DeprovisionModuleClientAsync(moduleName, ct);
                return Results.NoContent();
            })
            .WithMetadata(IssuerOperations.ClientsDelete)
            .Produces(StatusCodes.Status204NoContent);

        group.MapPost("/subjects/{subject}/revoke", async (string subject, ITokenRevoker revoker, CancellationToken ct) =>
                Results.Ok(new Revoked(await revoker.RevokeSubjectAsync(subject, ct))))
            .WithMetadata(IssuerOperations.TokensRevoke)
            .Produces<Revoked>(StatusCodes.Status200OK);

        group.MapPost("/authorizations/{authorizationId}/revoke", async (string authorizationId, ITokenRevoker revoker, CancellationToken ct) =>
            {
                var revoked = await revoker.RevokeAuthorizationAsync(authorizationId, ct);
                return revoked.IsSuccess ? Results.Ok(new Revoked(revoked.Value)) : revoked.ToHttpResult();
            })
            .WithMetadata(IssuerOperations.TokensRevoke)
            .Produces<Revoked>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapPost("/tokens/{tokenId}/revoke", async (string tokenId, ITokenRevoker revoker, CancellationToken ct) =>
                (await revoker.RevokeTokenAsync(tokenId, ct)).ToHttpResult())
            .WithMetadata(IssuerOperations.TokensRevoke)
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapGet("/security/revoked-tokens", async (IRevokedTokensSource revoked, CancellationToken ct) =>
                Results.Ok(await revoked.GetRevokedTokensAsync(ct)))
            .WithMetadata(IssuerOperations.TokensRevoke)
            .Produces<IReadOnlyCollection<RevokedToken>>(StatusCodes.Status200OK);

        return group;
    }
}

/// <summary>How many tokens a revocation revoked.</summary>
/// <param name="Count">The tokens revoked, those already revoked or expired not counted.</param>
public sealed record Revoked(int Count);
