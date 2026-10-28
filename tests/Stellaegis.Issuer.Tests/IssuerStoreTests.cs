using System.Data.Common;
using System.Globalization;
using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OpenIddict.EntityFrameworkCore.Models;
using Stellaegis.Issuer.Client;
using Stellaegis.Primitives;
using Stellaegis.Primitives.AspNetCore;
using Stellaegis.Primitives.Data;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Issuer.Tests;

/// <summary>A database of an engine for the store tests, installed from the frozen script of its adapter.</summary>
public interface IIssuerDatabaseFixture : IAsyncLifetime
{
    /// <summary>The connection string the issuer uses, under the application's role.</summary>
    string AppConnectionString { get; }

    /// <summary>Why the database cannot be used, or <see langword="null"/> when it can.</summary>
    string? Unavailable { get; }

    /// <summary>Skips the calling test when the database cannot be used.</summary>
    void SkipWhenUnavailable();

    /// <summary>Opens a connection to the test database, under the application's role or the installer's.</summary>
    Task<DbConnection> OpenAsync(bool asApplication, CancellationToken cancellationToken);

    /// <summary>Empties the four tables, so that a test starts from nothing without reinstalling the schema.</summary>
    Task ClearAsync(CancellationToken cancellationToken);
}

/// <summary>
/// The issuer on the stores of an engine, the schema installed by the fixture from the frozen script and never
/// created by EF Core: the flows of the test server replayed against the real engine, under the application's
/// role, and what the installation and the verification of the database do. Every engine runs the same scenarios;
/// a derived class says only how its adapter registers and what its catalogue answers.
/// </summary>
public abstract class IssuerStoreTests(IIssuerDatabaseFixture database) : IAsyncLifetime
{
    /// <summary>The frame the databases are installed for: the issuer fits every frame, this one has no compartment.</summary>
    public static readonly ApplicationFrame Frame = ApplicationFrame.WithoutCompartments;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>The declaration of the adapter's database.</summary>
    protected abstract ModuleDatabase Declaration { get; }

    /// <summary>The configuration key of the adapter's connection string.</summary>
    protected abstract string ConnectionStringKey { get; }

    /// <summary>Registers the issuer on the adapter, the options in code.</summary>
    protected abstract void AddIssuer(IServiceCollection services, string connectionString, Action<IssuerOptions> configure);

    /// <summary>Registers the issuer on the adapter, the options from the configuration.</summary>
    protected abstract void AddIssuer(IServiceCollection services, IConfiguration configuration);

    /// <summary>What the test server adds for its connections to run under the application's role, if anything.</summary>
    protected virtual void UnderApplicationRole(IServiceCollection services)
    {
    }

    /// <summary>The tables of the schema <c>oidc</c>, sorted by name ordinally.</summary>
    protected abstract string TablesSql { get; }

    /// <summary>Renames the record of the installation away, or back.</summary>
    protected abstract string RenameRecordSql(bool back);

    /// <summary>Asserts that <paramref name="write"/> is refused for want of a right.</summary>
    protected abstract Task AssertRefusedAsync(Func<Task> write);

    /// <inheritdoc/>
    public async ValueTask InitializeAsync()
    {
        if (database.Unavailable is null)
            await database.ClearAsync(Ct);
    }

    /// <inheritdoc/>
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    /// <summary>The issuer assembled on the test server over the installed database, as the SQLite host is.</summary>
    private WebApplicationBuilder Builder(Action<IssuerOptions>? configure = null)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = Environments.Development });
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Services.AddStellaegisFrame(Frame);
        builder.Services.AddSingleton<IEventPublisher, CapturingEventPublisher>();
        builder.Services.AddSingleton<RefusingSubjects>();
        builder.Services.AddStellaegisActorAdmission(provider => provider.GetRequiredService<RefusingSubjects>());
        builder.Services.AddTestAuthentication();
        AddIssuer(builder.Services, database.AppConnectionString, options =>
        {
            options.Certificates.UseDevelopmentCertificates = true;
            options.RequireHttps = false;
            options.EncryptAccessTokens = false;
            configure?.Invoke(options);
        });
        UnderApplicationRole(builder.Services);
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
            command.CommandText = TablesSql;
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
    public async Task A_client_id_and_a_scope_name_are_compared_case_sensitively()
    {
        database.SkipWhenUnavailable();
        await using var app = await Builder().StartAsync(Ct, ensureCreated: false);
        using var scope = app.Services.CreateScope();
        var catalog = scope.ServiceProvider.GetRequiredService<IssuerCatalog>();

        // OAuth identifiers are case-sensitive (RFC 6749): two client_id that differ by case are two clients, and a
        // scope requested with another case is not found, on every engine.
        Assert.True((await catalog.CreateScopeAsync(new ScopeDefinition("documents"), Ct)).IsSuccess);
        Assert.True((await catalog.CreateClientAsync(new ClientDefinition("desktop", DisplayName: "lower", RedirectUris: [IssuerTestHost.RedirectUri]), Ct)).IsSuccess);
        Assert.True((await catalog.CreateClientAsync(new ClientDefinition("Desktop", DisplayName: "upper", RedirectUris: [IssuerTestHost.RedirectUri]), Ct)).IsSuccess);

        Assert.Equal("lower", (await catalog.GetClientAsync("desktop", Ct)).Value.DisplayName);
        Assert.Equal("upper", (await catalog.GetClientAsync("Desktop", Ct)).Value.DisplayName);
        Assert.True((await catalog.GetClientAsync("DESKTOP", Ct)).IsFailure);

        var scopes = scope.ServiceProvider.GetRequiredService<OpenIddict.Abstractions.IOpenIddictScopeManager>();
        Assert.NotNull(await scopes.FindByNameAsync("documents", Ct));
        Assert.Null(await scopes.FindByNameAsync("DOCUMENTS", Ct));
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

        // The prompt of a client is kept in the properties of its application.
        var desktop = await catalog.CreateClientAsync(new ClientDefinition("desktop", Kind: ClientKind.Native, RedirectUris: ["http://127.0.0.1/callback"]) { Prompt = ClientPrompt.Login }, Ct);
        Assert.True(desktop.IsSuccess, desktop.Error?.ToString());
        Assert.Equal(ClientPrompt.Login, (await catalog.GetClientAsync("desktop", Ct)).Value.Prompt);
        Assert.True((await catalog.DeleteClientAsync("desktop", Ct)).IsSuccess);

        Assert.True((await catalog.DeleteClientAsync("reports", Ct)).IsSuccess);
        Assert.True((await catalog.GetClientAsync("reports", Ct)).IsFailure);
        Assert.True((await catalog.DeleteScopeAsync("documents", Ct)).IsSuccess);
    }

    [Fact]
    public async Task A_generic_host_verifies_the_installed_database_at_startup()
    {
        database.SkipWhenUnavailable();
        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { EnvironmentName = Environments.Development });
        builder.Logging.ClearProviders();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [ConnectionStringKey] = database.AppConnectionString,
            ["Stellaegis:Issuer:Certificates:UseDevelopmentCertificates"] = "true",
            ["Stellaegis:Issuer:RequireHttps"] = "false",
        });
        builder.Services
            .AddStellaegisFrame(Frame)
            .AddStellaegisValidation()
            .AddStellaegisDatabaseVerification();
        AddIssuer(builder.Services, builder.Configuration);
        using var host = builder.Build();

        await host.StartAsync(Ct);
        await host.StopAsync(Ct);

        Assert.Equal([Declaration], host.Services.GetStellaegisModuleDatabases());
        Assert.Contains(host.Services.GetStellaegisModules(), module => module.Module == typeof(IssuerModule));
    }

    [Fact]
    public async Task A_host_whose_database_is_not_installed_refuses_to_start()
    {
        database.SkipWhenUnavailable();
        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { EnvironmentName = Environments.Development });
        builder.Logging.ClearProviders();
        builder.Services
            .AddStellaegisFrame(Frame)
            .AddStellaegisDatabaseVerification();
        AddIssuer(builder.Services, database.AppConnectionString, options =>
        {
            options.Certificates.UseDevelopmentCertificates = true;
            options.RequireHttps = false;
        });
        using var host = builder.Build();
        await using (var connection = await database.OpenAsync(asApplication: false, Ct))
        await using (var command = connection.CreateCommand())
        {
            // The record of the installation is what the verification reads first: without it, nothing was installed.
            command.CommandText = RenameRecordSql(back: false);
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
            command.CommandText = RenameRecordSql(back: true);
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
            read.CommandText = $"select count(*) from {Declaration.MigrationsTable}";
            Assert.Equal(1L, Convert.ToInt64(await read.ExecuteScalarAsync(Ct), CultureInfo.InvariantCulture));
        }

        await using var write = connection.CreateCommand();
        write.CommandText = $"insert into {Declaration.MigrationsTable} (version, script_name, checksum, applied_by) values (9, 'x', 'x', 'x')";
        await AssertRefusedAsync(() => write.ExecuteNonQueryAsync(Ct));
    }
}
