using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Stellaegis.Issuer.SqlServer;
using Stellaegis.Primitives.Data;

namespace Stellaegis.Issuer.Tests;

/// <summary>
/// The issuer on its SQL Server stores (<see cref="IssuerStoreTests"/>), in a case-insensitive database, EF Core
/// running as the application's user.
/// </summary>
[Collection(SqlServerCollection.Name)]
public sealed class SqlServerTests(SqlServerFixture database) : IssuerStoreTests(database)
{
    private readonly SqlServerFixture _database = database;

    /// <inheritdoc/>
    protected override ModuleDatabase Declaration => IssuerDatabase.Value;

    /// <inheritdoc/>
    protected override string ConnectionStringKey => "Stellaegis:Issuer:SqlServer:ConnectionString";

    /// <inheritdoc/>
    protected override void AddIssuer(IServiceCollection services, string connectionString, Action<IssuerOptions> configure)
        => services.AddStellaegisIssuerSqlServer(options => options.ConnectionString = connectionString, configure);

    /// <inheritdoc/>
    protected override void AddIssuer(IServiceCollection services, IConfiguration configuration)
        => services.AddStellaegisIssuerSqlServer(configuration);

    /// <inheritdoc/>
    protected override void UnderApplicationRole(IServiceCollection services)
        => services.ConfigureDbContext<IssuerDbContext>(db => db.AddInterceptors(_database.Interceptor));

    /// <inheritdoc/>
    protected override string TablesSql
        => $"select name from sys.tables where schema_id = schema_id(N'{IssuerDatabase.Schema}') order by name collate Latin1_General_100_BIN2";

    /// <inheritdoc/>
    protected override string RenameRecordSql(bool back) => back
        ? $"exec sp_rename N'{IssuerDatabase.Schema}._schema_migrations_gone', N'_schema_migrations'"
        : $"exec sp_rename N'{IssuerDatabase.Value.MigrationsTable}', N'_schema_migrations_gone'";

    /// <inheritdoc/>
    protected override async Task AssertRefusedAsync(Func<Task> write)
    {
        var exception = await Assert.ThrowsAsync<SqlException>(write);
        Assert.Equal(229, exception.Number);   // the permission was denied
    }

    [Fact]
    public void An_empty_connection_string_refuses_the_registration()
    {
        var services = new ServiceCollection();

        var exception = Assert.Throws<InvalidOperationException>(() =>
            services.AddStellaegisIssuerSqlServer(options => options.ConnectionString = " ", options => options.Certificates.UseDevelopmentCertificates = true));

        Assert.Contains("ConnectionString is required", exception.Message);
    }

    [Fact]
    public void The_declaration_runs_on_SqlServer_with_its_own_script()
    {
        Assert.Equal(DatabaseEngine.SqlServer, IssuerDatabase.Value.Engine);
        Assert.Equal(["0001_oidc.sql"], IssuerDatabase.Value.Scripts.Select(script => script.FileName));
        Assert.Contains("collate Latin1_General_100_BIN2", IssuerDatabase.Value.Scripts[0].Sql);
    }
}
