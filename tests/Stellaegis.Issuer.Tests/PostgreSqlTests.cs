using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Stellaegis.Issuer.PostgreSQL;
using Stellaegis.Primitives.Data;

namespace Stellaegis.Issuer.Tests;

/// <summary>
/// The issuer on its PostgreSQL stores (<see cref="IssuerStoreTests"/>), the application connecting under an
/// ordinary role.
/// </summary>
[Collection(PostgreSqlCollection.Name)]
public sealed class PostgreSqlTests(PostgreSqlFixture database) : IssuerStoreTests(database)
{
    /// <inheritdoc/>
    protected override ModuleDatabase Declaration => IssuerDatabase.Value;

    /// <inheritdoc/>
    protected override string ConnectionStringKey => "Stellaegis:Issuer:PostgreSQL:ConnectionString";

    /// <inheritdoc/>
    protected override void AddIssuer(IServiceCollection services, string connectionString, Action<IssuerOptions> configure)
        => services.AddStellaegisIssuerPostgreSQL(options => options.ConnectionString = connectionString, configure);

    /// <inheritdoc/>
    protected override void AddIssuer(IServiceCollection services, IConfiguration configuration)
        => services.AddStellaegisIssuerPostgreSQL(configuration);

    /// <inheritdoc/>
    protected override string TablesSql => $"select tablename from pg_tables where schemaname = '{IssuerDatabase.Schema}' order by tablename";

    /// <inheritdoc/>
    protected override string RenameRecordSql(bool back) => back
        ? $"alter table {IssuerDatabase.Schema}._schema_migrations_gone rename to _schema_migrations"
        : $"alter table {IssuerDatabase.Value.MigrationsTable} rename to _schema_migrations_gone";

    /// <inheritdoc/>
    protected override async Task AssertRefusedAsync(Func<Task> write)
    {
        var exception = await Assert.ThrowsAsync<PostgresException>(write);
        Assert.Equal("42501", exception.SqlState);   // insufficient privilege
    }

    [Fact]
    public void An_empty_connection_string_refuses_the_registration()
    {
        var services = new ServiceCollection();

        var exception = Assert.Throws<InvalidOperationException>(() =>
            services.AddStellaegisIssuerPostgreSQL(options => options.ConnectionString = " ", options => options.Certificates.UseDevelopmentCertificates = true));

        Assert.Contains("ConnectionString is required", exception.Message);
    }
}
