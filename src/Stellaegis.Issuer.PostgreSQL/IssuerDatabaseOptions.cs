using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Issuer.PostgreSQL;

/// <summary>
/// The options of the PostgreSQL stores of the issuer, bound from <see cref="SectionName"/> or configured in
/// code, and validated when the host starts.
/// <code>
/// Stellaegis:Issuer:PostgreSQL:ConnectionString = Host=…;Database=…;Username=…
/// </code>
/// </summary>
public sealed class IssuerDatabaseOptions : IValidatableOptions
{
    /// <summary>The configuration section of the adapter, <c>Stellaegis:Issuer:PostgreSQL</c>.</summary>
    public const string SectionName = "Stellaegis:Issuer:PostgreSQL";

    /// <summary>
    /// The connection string to the database holding the <c>oidc</c> schema, under the application's role — the
    /// one the installation granted its data rights, never the one that owns the schema.
    /// </summary>
    public string ConnectionString { get; set; } = string.Empty;

    /// <inheritdoc/>
    public string? FindError()
        => string.IsNullOrWhiteSpace(ConnectionString) ? $"{nameof(ConnectionString)} is required." : null;
}
