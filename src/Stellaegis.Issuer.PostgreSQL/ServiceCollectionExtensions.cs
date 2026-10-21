using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;
using Stellaegis.Primitives;
using Stellaegis.Primitives.Data;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Issuer.PostgreSQL;

/// <summary>Registers the issuer on its PostgreSQL stores.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the issuer (<see cref="Issuer.ServiceCollectionExtensions.AddStellaegisIssuer(IServiceCollection, IConfiguration, Action{DbContextOptionsBuilder}, string)"/>,
    /// its options from <paramref name="issuerSectionName"/>) with its stores on PostgreSQL, the connection bound
    /// from <paramref name="databaseSectionName"/>, and declares its database, <see cref="IssuerDatabase.Value"/>,
    /// which a host verifies at startup under the application's role with <c>AddStellaegisDatabaseVerification()</c>,
    /// and which an installer installs under an administration role.
    /// </summary>
    public static IServiceCollection AddStellaegisIssuerPostgreSQL(
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
        var dataSource = DataSource(database);
        services.AddStellaegisIssuer(configuration, db => db.UseNpgsql(dataSource), issuerSectionName);
        return services.AddDatabase(dataSource);
    }

    /// <summary>
    /// Registers the issuer on its PostgreSQL stores as
    /// <see cref="AddStellaegisIssuerPostgreSQL(IServiceCollection, IConfiguration, string, string)"/> does, the
    /// options configured in code.
    /// </summary>
    public static IServiceCollection AddStellaegisIssuerPostgreSQL(
        this IServiceCollection services,
        Action<IssuerDatabaseOptions> configureDatabase,
        Action<IssuerOptions> configure)
    {
        Guard.NotNull(configureDatabase);
        Guard.NotNull(configure);

        var database = new IssuerDatabaseOptions();
        configureDatabase(database);
        services.AddStellaegisOptions(configureDatabase);
        var dataSource = DataSource(database);
        services.AddStellaegisIssuer(configure, db => db.UseNpgsql(dataSource));
        return services.AddDatabase(dataSource);
    }

    // The connection string is read once, at registration: the data source EF Core and the verification open on
    // is built here, and an empty connection string refuses the registration rather than the first request.
    private static NpgsqlDataSource DataSource(IssuerDatabaseOptions database)
    {
        if (database.FindError() is { } error)
            throw new InvalidOperationException($"{nameof(IssuerDatabaseOptions)}: {error}");
        return NpgsqlDataSource.Create(database.ConnectionString);
    }

    private static IServiceCollection AddDatabase(this IServiceCollection services, NpgsqlDataSource dataSource)
    {
        services.TryAddSingleton(dataSource);
        services.AddStellaegisModuleDatabase(IssuerDatabase.Value, (_, cancellationToken) => OpenAsync(dataSource, cancellationToken));
        return services;
    }

    private static async Task<DbConnection> OpenAsync(NpgsqlDataSource dataSource, CancellationToken cancellationToken)
        => await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
}
