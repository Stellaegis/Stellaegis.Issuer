using System.Net;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Npgsql;
using OpenIddict.EntityFrameworkCore.Models;
using Stellaegis.Issuer.PostgreSQL;
using Stellaegis.Issuer.Client;
using Stellaegis.Primitives;
using Stellaegis.Primitives.AspNetCore;
using Stellaegis.Primitives.Data;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Issuer.Tests;

/// <summary>
/// The issuer on its PostgreSQL stores, the schema installed by the fixture from the frozen script and never
/// created by EF Core: the flows of the test server replayed against the real engine, under the application's
/// role, and what the installation and the verification of the database do.
/// </summary>
[Collection(PostgreSqlCollection.Name)]
public sealed class PostgreSqlTests(PostgreSqlFixture database) : IAsyncLifetime
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <inheritdoc/>
    public async ValueTask InitializeAsync()
    {
        if (database.Unavailable is null)
            await database.ClearAsync(Ct);
    }

    /// <inheritdoc/>
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    /// <summary>The issuer assembled on the test server over the installed PostgreSQL database, as the SQLite host is.</summary>
    private WebApplicationBuilder Builder(Action<IssuerOptions>? configure = null)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = Environments.Development });
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Services.AddStellaegisFrame(PostgreSqlFixture.Frame);
        builder.Services.AddSingleton<IEventPublisher, CapturingEventPublisher>();
        builder.Services.AddSingleton<RefusingSubjects>();
        builder.Services.AddStellaegisActorAdmission(provider => provider.GetRequiredService<RefusingSubjects>());
        builder.Services.AddTestAuthentication();
        builder.Services.AddStellaegisIssuerPostgreSQL(
            options => options.ConnectionString = database.AppConnectionString,
            options =>
            {
                options.Certificates.UseDevelopmentCertificates = true;
                options.RequireHttps = false;
                options.EncryptAccessTokens = false;
                configure?.Invoke(options);
            });
        builder.Services.AddStellaegisIssuerAdmission();
        return builder;
    }

    [Fact]
    public async Task The_EF_model_reads_the_schema_the_script_installed()
    {
        database.SkipWhenUnavailable();
        await using var app = await Builder().StartAsync(Ct, ensureCreated: false);

        // The four tables are the script's, in oidc, and nothing else.
        await using (var connection = await database.OpenAsync(asApplication: true, Ct))
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = $"select tablename from pg_tables where schemaname = '{IssuerDatabase.Schema}' order by tablename";
            var tables = new List<string>();
            await using var reader = await command.ExecuteReaderAsync(Ct);
            while (await reader.ReadAsync(Ct))
                tables.Add(reader.GetString(0));
            Assert.Equal(["_schema_migrations", "applications", "authorizations", "scopes", "tokens"], tables);
        }

        // A client written by the catalog through OpenIddict is read back by EF Core through the same model.
        await app.DeclarePublicClientAsync("desktop", "documents", Ct);
        using var scope = app.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IssuerDbContext>();
        var application = await db.Set<OpenIddictEntityFrameworkCoreApplication>().SingleAsync(a => a.ClientId == "desktop", Ct);
        Assert.Equal("public", application.ClientType);
        Assert.Contains("documents", await db.Set<OpenIddictEntityFrameworkCoreScope>().Select(s => s.Name).ToListAsync(Ct));
        Assert.Empty(db.Database.GetMigrations());   // no EF Core migration exists: the script is the schema
    }

    [Fact]
    public async Task A_public_client_gets_its_tokens_by_code_and_PKCE_refreshes_them_and_is_refused_once_the_host_no_longer_admits_it()
    {
        database.SkipWhenUnavailable();
        await using var app = await Builder().StartAsync(Ct, ensureCreated: false);
        await app.DeclarePublicClientAsync(ct: Ct);

        var (code, verifier) = await app.AuthorizeAsync("jane", ct: Ct);
        var tokens = await app.ExchangeCodeAsync(code, verifier, ct: Ct);
        Assert.Equal(HttpStatusCode.OK, tokens.Status);
        Assert.Equal("jane", IssuerTestHost.Payload(tokens.AccessToken).GetProperty("sub").GetString());

        var refreshed = await app.RefreshAsync(tokens.RefreshToken, ct: Ct);
        Assert.Equal(HttpStatusCode.OK, refreshed.Status);
        Assert.NotEqual(tokens.AccessToken, refreshed.AccessToken);

        app.Refusing().Refused.Add("jane");
        var refused = await app.RefreshAsync(refreshed.RefreshToken, ct: Ct);
        Assert.Equal(HttpStatusCode.BadRequest, refused.Status);
        Assert.Equal("invalid_grant", refused.Error);
    }

    [Fact]
    public async Task A_module_is_provisioned_and_its_client_gets_a_token_by_its_credentials()
    {
        database.SkipWhenUnavailable();
        await using var app = await Builder().StartAsync(Ct, ensureCreated: false);
        ProvisionedClient documents;
        using (var scope = app.Services.CreateScope())
        {
            var provisioned = await scope.ServiceProvider.GetRequiredService<IOidcClientProvisioner>().ProvisionModuleClientAsync("documents", Ct);
            Assert.True(provisioned.IsSuccess, provisioned.Error?.ToString());
            documents = provisioned.Value;
        }

        var tokens = await app.ClientCredentialsAsync(documents.ClientId, documents.Secret, "documents", Ct);

        Assert.Equal(HttpStatusCode.OK, tokens.Status);
        var payload = IssuerTestHost.Payload(tokens.AccessToken);
        Assert.Equal(documents.ClientId, payload.GetProperty("sub").GetString());
    }

    [Fact]
    public async Task Revoking_a_subject_announces_its_access_token_and_the_local_source_lists_it()
    {
        database.SkipWhenUnavailable();
        await using var app = await Builder().StartAsync(Ct, ensureCreated: false);
        await app.DeclarePublicClientAsync(ct: Ct);
        var (code, verifier) = await app.AuthorizeAsync("jane", ct: Ct);
        var tokens = await app.ExchangeCodeAsync(code, verifier, ct: Ct);
        var tokenId = IssuerTestHost.Payload(tokens.AccessToken).GetProperty("oi_tkn_id").GetString()!;

        using var scope = app.Services.CreateScope();
        await scope.ServiceProvider.GetRequiredService<ITokenRevoker>().RevokeSubjectAsync("jane", Ct);

        Assert.Contains(app.Events().Events, e => e is TokenRevokedEvent revoked && revoked.TokenId == tokenId);
        var listed = await scope.ServiceProvider.GetRequiredService<IRevokedTokensSource>().GetRevokedTokensAsync(Ct);
        Assert.Contains(listed, token => token.TokenId == tokenId);
        Assert.True(app.Services.GetRequiredService<RevokedTokens>().IsRevoked(tokenId));
    }

    [Fact]
    public async Task Clients_and_scopes_are_created_read_changed_and_deleted_on_the_engine()
    {
        database.SkipWhenUnavailable();
        await using var app = await Builder().StartAsync(Ct, ensureCreated: false);
        using var scope = app.Services.CreateScope();
        var catalog = scope.ServiceProvider.GetRequiredService<IssuerCatalog>();

        Assert.True((await catalog.CreateScopeAsync(new ScopeDefinition("documents"), Ct)).IsSuccess);
        var created = await catalog.CreateClientAsync(new ClientDefinition("reports", Kind: ClientKind.Confidential, Scopes: ["documents"]), Ct);
        Assert.True(created.IsSuccess, created.Error?.ToString());
        Assert.NotEmpty(created.Value.Secret!);
        Assert.Equal("reports", created.Value.Client.ClientId);

        var read = await catalog.GetClientAsync("reports", Ct);
        Assert.True(read.IsSuccess);
        Assert.Equal(ClientKind.Confidential, read.Value.Kind);
        Assert.Equal(["documents"], read.Value.Scopes);

        Assert.True((await catalog.DeleteClientAsync("reports", Ct)).IsSuccess);
        Assert.True((await catalog.GetClientAsync("reports", Ct)).IsFailure);
        Assert.True((await catalog.DeleteScopeAsync("documents", Ct)).IsSuccess);
    }

    [Fact]
    public async Task A_generic_host_verifies_the_installed_database_at_startup_under_the_application_role()
    {
        database.SkipWhenUnavailable();
        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { EnvironmentName = Environments.Development });
        builder.Logging.ClearProviders();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Stellaegis:Issuer:PostgreSQL:ConnectionString"] = database.AppConnectionString,
            ["Stellaegis:Issuer:Certificates:UseDevelopmentCertificates"] = "true",
            ["Stellaegis:Issuer:RequireHttps"] = "false",
        });
        builder.Services
            .AddStellaegisFrame(PostgreSqlFixture.Frame)
            .AddStellaegisValidation()
            .AddStellaegisDatabaseVerification()
            .AddStellaegisIssuerPostgreSQL(builder.Configuration);
        using var host = builder.Build();

        await host.StartAsync(Ct);
        await host.StopAsync(Ct);

        Assert.Equal([IssuerDatabase.Value], host.Services.GetStellaegisModuleDatabases());
        Assert.Contains(host.Services.GetStellaegisModules(), module => module.Module == typeof(IssuerModule));
    }

    [Fact]
    public async Task A_host_whose_database_is_not_installed_refuses_to_start()
    {
        database.SkipWhenUnavailable();
        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { EnvironmentName = Environments.Development });
        builder.Logging.ClearProviders();
        builder.Services
            .AddStellaegisFrame(PostgreSqlFixture.Frame)
            .AddStellaegisDatabaseVerification()
            .AddStellaegisIssuerPostgreSQL(
                options => options.ConnectionString = database.AppConnectionString,
                options =>
                {
                    options.Certificates.UseDevelopmentCertificates = true;
                    options.RequireHttps = false;
                });
        using var host = builder.Build();
        await using (var connection = await database.OpenAsync(asApplication: false, Ct))
        await using (var command = connection.CreateCommand())
        {
            // The record of the installation is what the verification reads first: without it, nothing was installed.
            command.CommandText = $"alter table {IssuerDatabase.Value.MigrationsTable} rename to _schema_migrations_gone";
            await command.ExecuteNonQueryAsync(Ct);
        }

        try
        {
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => host.StartAsync(Ct));
            Assert.Contains("issuer is not installed", exception.Message);
        }
        finally
        {
            await using var connection = await database.OpenAsync(asApplication: false, Ct);
            await using var command = connection.CreateCommand();
            command.CommandText = $"alter table {IssuerDatabase.Schema}._schema_migrations_gone rename to _schema_migrations";
            await command.ExecuteNonQueryAsync(Ct);
        }
    }

    [Fact]
    public async Task The_record_of_the_installation_is_closed_to_the_application_role()
    {
        database.SkipWhenUnavailable();
        await using var connection = await database.OpenAsync(asApplication: true, Ct);

        await using (var read = connection.CreateCommand())
        {
            read.CommandText = $"select count(*) from {IssuerDatabase.Value.MigrationsTable}";
            Assert.Equal(1L, await read.ExecuteScalarAsync(Ct));
        }

        await using var write = connection.CreateCommand();
        write.CommandText = $"insert into {IssuerDatabase.Value.MigrationsTable} (version, script_name, checksum, applied_by) values (9, 'x', 'x', 'x')";
        var exception = await Assert.ThrowsAsync<PostgresException>(() => write.ExecuteNonQueryAsync(Ct));
        Assert.Equal("42501", exception.SqlState);   // insufficient privilege
    }

    [Fact]
    public async Task An_empty_connection_string_refuses_the_registration()
    {
        var services = new ServiceCollection();

        var exception = Assert.Throws<InvalidOperationException>(() =>
            services.AddStellaegisIssuerPostgreSQL(options => options.ConnectionString = " ", options => options.Certificates.UseDevelopmentCertificates = true));

        Assert.Contains("ConnectionString is required", exception.Message);
    }
}
