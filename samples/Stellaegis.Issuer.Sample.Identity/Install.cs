using System.Data.Common;
using Microsoft.Extensions.Hosting.Internal;
using Npgsql;
using Stellaegis.Identity;
using Stellaegis.Identity.PostgreSQL;
using Stellaegis.Issuer.PostgreSQL;
using Stellaegis.Primitives;
using Stellaegis.Primitives.Data;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Issuer.Sample.Identity;

/// <summary>
/// The installation of the example, apart from the application and under another role: the database and the
/// application's role created if missing; the <c>ident</c> and <c>oidc</c> schemas installed by the life cycle of
/// Primitives under the administration connection — one database, two schemas, one role: the example shares the
/// instance, a deployment splits them by configuration alone —; the first administrator created by the services
/// of the accounts; the public client of the desktop declared, and the credentials of the inventory module
/// provisioned, by the services of the issuer. Run again, it changes nothing: the scripts are recorded, the
/// administrator and the clients exist, the configuration is re-applied.
/// <code>
/// dotnet run -- install --admin-email admin@acme.test --admin-password 'Correct-Horse-9' [--display-name Admin]
/// </code>
/// </summary>
public static class Install
{
    /// <summary>The native client of the desktop application: public, authorization code with PKCE, back on the loopback whatever its port.</summary>
    public const string DesktopClientId = "desktop";

    /// <summary>The module the resource server apart serves, whose credentials the installation provisions.</summary>
    public const string InventoryModule = "inventory";

    public static async Task<int> RunAsync(string[] args)
    {
        var email = Argument(args, "--admin-email");
        var password = Argument(args, "--admin-password");
        var displayName = Argument(args, "--display-name") ?? "Administrator";
        if (email is null || password is null)
        {
            Console.Error.WriteLine("usage: install --admin-email <email> --admin-password <password> [--display-name <name>]");
            return 2;
        }

        // The example is a development host: its issuer signs with development certificates, which only the
        // Development environment accepts. The installer reads the same configuration as the application.
        var environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Development";
        var configuration = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json", optional: false)
            .AddJsonFile($"appsettings.{environment}.json", optional: true)
            .AddUserSecrets<LoggingMailer>(optional: true)
            .AddEnvironmentVariables()
            .Build();

        // The application's connection string names the database and the role the application runs under; the
        // installer's connection string reaches the server under a role that may create both.
        var application = new NpgsqlConnectionStringBuilder(configuration["Stellaegis:Identity:PostgreSQL:ConnectionString"]
            ?? throw new InvalidOperationException("Stellaegis:Identity:PostgreSQL:ConnectionString is not configured."));
        var installer = new NpgsqlConnectionStringBuilder(configuration["Sample:Install:ConnectionString"]
            ?? throw new InvalidOperationException("Sample:Install:ConnectionString is not configured."));
        var role = application.Username ?? throw new InvalidOperationException("The application's connection string names no role.");
        var database = application.Database ?? throw new InvalidOperationException("The application's connection string names no database.");

        // 1. The database and the role, if missing.
        await using (var server = new NpgsqlConnection(installer.ConnectionString))
        {
            await server.OpenAsync();
            await using (var exists = new NpgsqlCommand("select 1 from pg_database where datname = @name", server))
            {
                exists.Parameters.AddWithValue("name", database);
                if (await exists.ExecuteScalarAsync() is null)
                {
                    await using var create = new NpgsqlCommand($"create database \"{database}\"", server);
                    await create.ExecuteNonQueryAsync();
                    Console.WriteLine($"Database {database} created.");
                }
            }
            await using (var createRole = new NpgsqlCommand(
                $"""
                do $$ begin
                  create role "{role}" login password '{application.Password?.Replace("'", "''")}';
                exception when duplicate_object or unique_violation then null;
                end $$;
                """, server))
            {
                await createRole.ExecuteNonQueryAsync();
            }
        }

        // 2. The two schemas, under the installer, which owns them; the application's role granted its rights.
        var adminOnDatabase = new NpgsqlConnectionStringBuilder(installer.ConnectionString) { Database = database }.ConnectionString;
        var report = await DatabaseLifecycle.InstallAsync(
            [IdentityDatabase.Value, IssuerDatabase.Value], SampleFrame.Value,
            async (_, ct) => { DbConnection c = new NpgsqlConnection(adminOnDatabase); await c.OpenAsync(ct); return c; },
            role);
        foreach (var applied in report.Applied)
            Console.WriteLine($"Applied: {applied}");
        foreach (var skipped in report.Skipped)
            Console.WriteLine($"Already applied: {skipped}");

        // 3. The data of the installation, by the services of the modules, under the application's role, as the
        // administration routes would: the installation is the one actor that creates them by itself.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IHostEnvironment>(new HostingEnvironment { EnvironmentName = environment, ApplicationName = "install", ContentRootPath = AppContext.BaseDirectory });
        services.AddStellaegisFrame(SampleFrame.Value);
        services.AddStellaegisIdentityPostgreSQL(configuration);
        services.AddStellaegisIssuerPostgreSQL(configuration);
        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();

        // 3a. The first administrator.
        var created = await scope.ServiceProvider.GetRequiredService<AccountAdministrationService>()
            .CreateAsync(email, displayName, password, Actor.Job("install"));
        if (created.IsSuccess)
            Console.WriteLine($"Administrator {email} created, {created.Value:N}.");
        else if (created.Error?.Code == IdentityErrors.EmailTakenCode)
            Console.WriteLine($"Administrator {email} exists already.");
        else
        {
            Console.Error.WriteLine($"The administrator was not created: {created.Error}");
            return 1;
        }

        // 3b. The credentials of the inventory module: its scope and its confidential client. The secret generated
        // here is shown once; the example overrides it with the one its configuration names, below, so that the
        // inventory host's configuration can name the same.
        var provisioner = scope.ServiceProvider.GetRequiredService<IOidcClientProvisioner>();
        var provisioned = await provisioner.ProvisionModuleClientAsync(InventoryModule);
        if (provisioned.IsSuccess)
            Console.WriteLine($"Module {InventoryModule} provisioned: client {provisioned.Value.ClientId}, secret {provisioned.Value.Secret} (shown once).");
        else if (provisioned.Error?.Code == IssuerErrors.ClientExistsCode)
            Console.WriteLine($"Module {InventoryModule} is provisioned already.");
        else
        {
            Console.Error.WriteLine($"The module {InventoryModule} was not provisioned: {provisioned.Error}");
            return 1;
        }

        // 3c. The scope of the issuer, which a service reads the revoked tokens with, granted to the inventory;
        // and the public client of the desktop, whose redirect URIs the configuration names.
        var catalog = scope.ServiceProvider.GetRequiredService<IssuerCatalog>();
        if ((await catalog.GetScopeAsync(IssuerModule.Name)).IsFailure)
        {
            var scopeCreated = await catalog.CreateScopeAsync(new ScopeDefinition(IssuerModule.Name, Description: "Reading the issuer: the revoked tokens, the scopes."));
            Console.WriteLine(scopeCreated.IsSuccess ? $"Scope {IssuerModule.Name} created." : $"The scope {IssuerModule.Name} was not created: {scopeCreated.Error}");
        }
        var inventory = await catalog.UpdateClientAsync(new ClientDefinition(InventoryModule, $"{InventoryModule} (module)", ClientKind.Confidential, Scopes: [InventoryModule, IssuerModule.Name]));
        Console.WriteLine(inventory.IsSuccess ? $"Client {InventoryModule} may request the scopes {InventoryModule} and {IssuerModule.Name}." : $"The client {InventoryModule} was not updated: {inventory.Error}");

        var desktopDefinition = new ClientDefinition(DesktopClientId, "The desktop application", ClientKind.Native, Scopes: ["email", "profile", InventoryModule]);
        var desktop = (await catalog.GetClientAsync(DesktopClientId)).IsFailure
            ? await catalog.CreateClientAsync(desktopDefinition)
            : await catalog.UpdateClientAsync(desktopDefinition);
        if (desktop.IsSuccess)
            Console.WriteLine($"Client {DesktopClientId} declared: native, authorization code with PKCE, redirect URIs {string.Join(", ", desktop.Value.Client.RedirectUris)} — the port of the loopback ignored.");
        else
        {
            Console.Error.WriteLine($"The client {DesktopClientId} was not declared: {desktop.Error}");
            return 1;
        }

        // 3d. What the environment configures of the clients declared — the secret of the inventory, the redirect
        // URIs of the desktop —, re-applied: Stellaegis:Issuer:Clients.
        var applied2 = await catalog.ApplyConfiguredClientsAsync();
        Console.WriteLine($"Configuration applied to: {string.Join(", ", applied2)}.");
        return 0;
    }

    private static string? Argument(string[] args, string name)
    {
        var index = Array.IndexOf(args, name);
        return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
    }
}
