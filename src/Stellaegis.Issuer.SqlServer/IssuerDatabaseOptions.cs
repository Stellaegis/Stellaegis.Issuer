using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Issuer.SqlServer;

/// <summary>
/// The options of the SQL Server stores of the issuer, bound from <see cref="SectionName"/> or configured in
/// code, and validated when the host starts.
/// <code>
/// Stellaegis:Issuer:SqlServer:ConnectionString = Server=…;Database=…;Integrated Security=true
/// </code>
/// </summary>
public sealed class IssuerDatabaseOptions : IValidatableOptions
{
    /// <summary>The configuration section of the adapter, <c>Stellaegis:Issuer:SqlServer</c>.</summary>
    public const string SectionName = "Stellaegis:Issuer:SqlServer";

    /// <summary>
    /// The connection string to the database holding the <c>oidc</c> schema, under a member of the application's
    /// role — the one the installation granted its data rights, never the login that owns the schema.
    /// </summary>
    public string ConnectionString { get; set; } = string.Empty;

    /// <inheritdoc/>
    public string? FindError()
        => string.IsNullOrWhiteSpace(ConnectionString) ? $"{nameof(ConnectionString)} is required." : null;
}
