using System.Data.Common;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Stellaegis.Issuer.SqlServer;
using Stellaegis.Primitives;
using Stellaegis.Primitives.Data;

namespace Stellaegis.Issuer.Tests;

/// <summary>The classes of the collection share one installed schema, and never run in parallel with one another.</summary>
[CollectionDefinition(SqlServerCollection.Name)]
public sealed class SqlServerCollection : ICollectionFixture<SqlServerFixture>
{
    /// <summary>The name of the collection.</summary>
    public const string Name = "SQL Server";
}

/// <summary>
/// A dedicated SQL Server database for the store tests, named by <c>STELLAEGIS_TEST_SQLSERVER</c> — the server the
/// family's tests use, under a login that may create databases — and skipped without it. The database
/// <c>stellaegis_issuer_tests</c> is created at every run, with a case-insensitive collation as an installation
/// would choose, and dropped after: its <c>oidc</c> schema is installed by the installation of the module from the
/// frozen script — never by EF Core —, and the application is the user <c>stellaegis_issuer_probe</c>, without
/// login, member of the role the installation created. Its connections take that identity by
/// <c>EXECUTE AS USER</c>, EF Core's through <see cref="ApplicationRoleInterceptor"/>, so that an instance accepting
/// integrated security only runs the tests. The verification at startup opens its own connection, under the login of
/// the variable: under the application's role, it is proven by the tests of <c>Stellaegis.Primitives.Data</c>.
/// </summary>
public sealed class SqlServerFixture : IIssuerDatabaseFixture
{
    private const string Variable = "STELLAEGIS_TEST_SQLSERVER";
    private const string Database = "stellaegis_issuer_tests";
    private const string AppRole = "stellaegis_issuer_app";
    private const string AppUser = "stellaegis_issuer_probe";

    private string _server = string.Empty;

    /// <summary>The connection string of the installer, which owns the schema; empty without the variable.</summary>
    public string AdminConnectionString { get; private set; } = string.Empty;

    /// <inheritdoc/>
    /// <remarks>The login of the variable, without pooling: <see cref="ApplicationRoleInterceptor"/> makes it the application.</remarks>
    public string AppConnectionString => AdminConnectionString;

    /// <inheritdoc/>
    public string? Unavailable { get; private set; }

    /// <inheritdoc/>
    public void SkipWhenUnavailable() => Assert.SkipWhen(Unavailable is not null, Unavailable ?? string.Empty);

    /// <summary>The interceptor that runs EF Core's connections as the application's user.</summary>
    public ApplicationRoleInterceptor Interceptor { get; } = new();

    /// <inheritdoc/>
    public async ValueTask InitializeAsync()
    {
        var configured = Environment.GetEnvironmentVariable(Variable);
        if (string.IsNullOrWhiteSpace(configured))
        {
            Unavailable = $"{Variable} is not set.";
            return;
        }

        // No pooling: a connection that took the identity of the application must not serve the installer.
        _server = new SqlConnectionStringBuilder(configured) { InitialCatalog = "master", Pooling = false }.ConnectionString;
        AdminConnectionString = new SqlConnectionStringBuilder(_server) { InitialCatalog = Database }.ConnectionString;

        try
        {
            await DropAsync();
            await using (var connection = new SqlConnection(_server))
            {
                await connection.OpenAsync();
                await ExecuteAsync(connection, $"create database [{Database}] collate French_100_CI_AS");
            }
            await using (var connection = new SqlConnection(AdminConnectionString))
            {
                await connection.OpenAsync();
                await ExecuteAsync(connection, $"create user [{AppUser}] without login");
            }

            await DatabaseLifecycle.InstallAsync([IssuerDatabase.Value], IssuerStoreTests.Frame, (_, ct) => OpenAsync(asApplication: false, ct), AppRole, Actor.Job("tests"));
            await using (var connection = new SqlConnection(AdminConnectionString))
            {
                await connection.OpenAsync();
                await ExecuteAsync(connection, $"alter role [{AppRole}] add member [{AppUser}]");
            }
        }
        catch (SqlException e)
        {
            Unavailable = $"No SQL Server for the store tests ({Variable} = '{configured}'): {e.Message}";
        }
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        if (Unavailable is null && _server.Length > 0)
            await DropAsync();
    }

    /// <inheritdoc/>
    public async Task<DbConnection> OpenAsync(bool asApplication, CancellationToken cancellationToken)
    {
        var connection = new SqlConnection(AdminConnectionString);
        await connection.OpenAsync(cancellationToken);
        if (asApplication)
            await ExecuteAsync(connection, ApplicationRoleInterceptor.ExecuteAs, cancellationToken);
        return connection;
    }

    /// <inheritdoc/>
    public async Task ClearAsync(CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(asApplication: false, cancellationToken);
        var schema = IssuerDatabase.Schema;
        await ExecuteAsync(connection,
            $"delete from {schema}.tokens; delete from {schema}.authorizations; delete from {schema}.applications; delete from {schema}.scopes;",
            cancellationToken);
    }

    private async Task DropAsync()
    {
        await using var connection = new SqlConnection(_server);
        await connection.OpenAsync();
        await ExecuteAsync(connection, $"""
            if db_id(N'{Database}') is not null
            begin
              alter database [{Database}] set single_user with rollback immediate;
              drop database [{Database}];
            end
            """);
    }

    private static async Task ExecuteAsync(DbConnection connection, string sql, CancellationToken cancellationToken = default)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    /// <summary>Runs every connection EF Core opens as the application's user, the way a member of its role connects.</summary>
    public sealed class ApplicationRoleInterceptor : DbConnectionInterceptor
    {
        /// <summary>The statement that takes the identity of the application's user.</summary>
        public const string ExecuteAs = $"execute as user = N'{AppUser}'";

        /// <inheritdoc/>
        public override void ConnectionOpened(DbConnection connection, ConnectionEndEventData eventData)
        {
            using var command = connection.CreateCommand();
            command.CommandText = ExecuteAs;
            command.ExecuteNonQuery();
        }

        /// <inheritdoc/>
        public override async Task ConnectionOpenedAsync(DbConnection connection, ConnectionEndEventData eventData, CancellationToken cancellationToken = default)
        {
            await using var command = connection.CreateCommand();
            command.CommandText = ExecuteAs;
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
    }
}
