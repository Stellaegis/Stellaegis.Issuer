using System.Data.Common;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Stellaegis.Primitives;
using Stellaegis.Primitives.Data;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Issuer.SqlServer;

/// <summary>Registers the issuer on its SQL Server stores.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the issuer (<see cref="Issuer.ServiceCollectionExtensions.AddStellaegisIssuer(IServiceCollection, IConfiguration, Action{DbContextOptionsBuilder}, string)"/>,
    /// its options from <paramref name="issuerSectionName"/>) with its stores on SQL Server, the connection bound
    /// from <paramref name="databaseSectionName"/>, and declares its database, <see cref="IssuerDatabase.Value"/>,
    /// which a host verifies at startup under the application's role with <c>AddStellaegisDatabaseVerification()</c>,
    /// and which an installer installs under an administration login.
    /// </summary>
    public static IServiceCollection AddStellaegisIssuerSqlServer(
        this IServiceCollection services,
        IConfiguration configuration,
        string databaseSectionName = IssuerDatabaseOptions.SectionName,
        string issuerSectionName = IssuerOptions.SectionName)
    {
        Guard.NotNull(configuration);
        Guard.NotWhiteSpace(databaseSectionName);

        var database = new IssuerDatabaseOptions();
        configuration.GetSection(databaseSectionName).Bind(database);
        services.AddStellaegisOptions<IssuerDatabaseOptions>(configuration, databaseSectionName);
        var connectionString = ConnectionString(database);
        services.AddStellaegisIssuer(configuration, db => db.UseSqlServer(connectionString), issuerSectionName);
        return services.AddDatabase(connectionString);
    }

    /// <summary>
    /// Registers the issuer on its SQL Server stores as
    /// <see cref="AddStellaegisIssuerSqlServer(IServiceCollection, IConfiguration, string, string)"/> does, the
    /// options configured in code.
    /// </summary>
    public static IServiceCollection AddStellaegisIssuerSqlServer(
        this IServiceCollection services,
        Action<IssuerDatabaseOptions> configureDatabase,
        Action<IssuerOptions> configure)
    {
        Guard.NotNull(configureDatabase);
        Guard.NotNull(configure);

        var database = new IssuerDatabaseOptions();
        configureDatabase(database);
        services.AddStellaegisOptions(configureDatabase);
        var connectionString = ConnectionString(database);
        services.AddStellaegisIssuer(configure, db => db.UseSqlServer(connectionString));
        return services.AddDatabase(connectionString);
    }

    // The connection string is read once, at registration: EF Core and the verification open on it, and an empty
    // connection string refuses the registration rather than the first request.
    private static string ConnectionString(IssuerDatabaseOptions database)
    {
        if (database.FindError() is { } error)
            throw new InvalidOperationException($"{nameof(IssuerDatabaseOptions)}: {error}");
        return database.ConnectionString;
    }

    private static IServiceCollection AddDatabase(this IServiceCollection services, string connectionString)
    {
        // The verification opens the connection it is handed, and disposes of it.
        services.AddStellaegisModuleDatabase(IssuerDatabase.Value, (_, _) => Task.FromResult<DbConnection>(new SqlConnection(connectionString)));
        return services;
    }
}
