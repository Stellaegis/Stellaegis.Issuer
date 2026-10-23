using Stellaegis.Primitives.Data;

namespace Stellaegis.Issuer.SqlServer;

/// <summary>
/// The database of the issuer on SQL Server, as <c>Stellaegis.Primitives.Data</c> installs and verifies it: the
/// schema <c>oidc</c> and its numbered scripts embedded in this package. The script is the DDL of the EF Core model
/// of the OpenIddict stores (<see cref="IssuerDbContext"/>), generated once from the model on the SQL Server
/// provider and frozen here, with a binary collation on the identifiers OAuth compares case-sensitively: EF Core
/// reads and writes these tables at run time and never creates nor migrates them. No row-level security: the module
/// has no compartment, every row belongs to the application. No table of an account either — the accounts are
/// <c>Stellaegis.Identity</c>'s, in a schema of their own.
/// </summary>
/// <remarks>
/// Registered by <see cref="ServiceCollectionExtensions.AddStellaegisIssuerSqlServer(Microsoft.Extensions.DependencyInjection.IServiceCollection, Microsoft.Extensions.Configuration.IConfiguration, string, string)"/>,
/// so that a host verifies it at startup under the application's role (<c>AddStellaegisDatabaseVerification</c>).
/// An installer installs it under an administration login: <c>DatabaseLifecycle.InstallAsync([IssuerDatabase.Value], frame, …)</c>.
/// </remarks>
public static class IssuerDatabase
{
    /// <summary>The schema holding the issuer's tables, <c>oidc</c> — the one <see cref="IssuerDbContext"/> maps.</summary>
    public const string Schema = IssuerDbContext.Schema;

    /// <summary>The declaration of the database.</summary>
    public static ModuleDatabase Value { get; } = ModuleDatabase.SqlServer<IssuerModule>(Schema)
        .WithScripts(SqlScripts.FromResources(typeof(IssuerDatabase).Assembly, "Stellaegis.Issuer.SqlServer.Sql.SqlServer"));
}
