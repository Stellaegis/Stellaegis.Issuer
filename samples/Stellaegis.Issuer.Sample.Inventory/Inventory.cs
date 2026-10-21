using System.Text.Json;
using Stellaegis.Primitives;
using Stellaegis.Primitives.AspNetCore;

namespace Stellaegis.Issuer.Sample.Inventory;

/// <summary>The one module of the resource server: an inventory, which the frame's compartment owns.</summary>
public sealed class InventoryModule : IStellaegisModule
{
    public static string Name => "inventory";

    public static ModuleDeclaration Declaration { get; } = ModuleDeclaration.Compartmented<InventoryModule>()
        .WithOperations(InventoryOperations.All);
}

/// <summary>The operations of the inventory, which its routes are labelled with.</summary>
public static class InventoryOperations
{
    /// <summary>Reading the items, <c>items.read</c>.</summary>
    public static readonly Operation ItemsRead = new("items", "read", OperationKind.Read);

    /// <summary>Reading the catalog of the issuer as this host sees it, <c>catalog.read</c>.</summary>
    public static readonly Operation CatalogRead = new("catalog", "read", OperationKind.Read);

    public static IReadOnlyList<Operation> All { get; } = [ItemsRead, CatalogRead];
}

/// <summary>An item of the inventory.</summary>
public sealed record Item(string Sku, string Name, int Quantity);

/// <summary>The routes of the inventory: the items, and what the issuer says when this host calls it as itself.</summary>
public static class InventoryEndpoints
{
    /// <summary>The named HTTP client that reaches the issuer's administration routes with this host's token.</summary>
    public const string IssuerClient = "issuer";

    private static readonly Item[] Items =
    [
        new("ACM-001", "Anvil, 50 kg", 12),
        new("ACM-002", "Rocket skates, pair", 3),
        new("ACM-003", "Giant rubber band", 40),
    ];

    public static RouteGroupBuilder MapInventoryEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("")
            .BelongsTo<InventoryModule>()
            .RequireRequestContext()
            .LoadsNoResource()
            .AddErrorTranslation();

        // The items of the compartment, with the actor the token names: the person, or the service.
        group.MapGet("/items", (IRequestContext context) => Results.Ok(new
            {
                space = context.Space?.ToString(),
                actor = context.Actor.ToString(),
                items = Items,
            }))
            .WithMetadata(InventoryOperations.ItemsRead);

        // This host calling the issuer as itself: the handler attaches the token obtained by its credentials.
        group.MapGet("/issuer/scopes", async (IHttpClientFactory clients, CancellationToken ct) =>
            {
                using var issuer = clients.CreateClient(IssuerClient);
                using var response = await issuer.GetAsync("scopes", ct);
                var body = await response.Content.ReadAsStringAsync(ct);
                return response.IsSuccessStatusCode
                    ? Results.Content(body, "application/json")
                    : Results.Problem(detail: body, statusCode: (int)response.StatusCode);
            })
            .WithMetadata(InventoryOperations.CatalogRead);

        return group;
    }
}
