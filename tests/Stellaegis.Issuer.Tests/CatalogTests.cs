using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Stellaegis.Issuer.Tests;

/// <summary>The clients and the scopes, as the installation declares them and the administration changes them.</summary>
public sealed class CatalogTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task A_module_is_provisioned_its_client_and_its_scope_rotated_and_deprovisioned()
    {
        await using var app = await IssuerTestHost.Builder().StartAsync(Ct);
        using var scope = app.Services.CreateScope();
        var provisioner = scope.ServiceProvider.GetRequiredService<IOidcClientProvisioner>();
        var catalog = scope.ServiceProvider.GetRequiredService<IssuerCatalog>();

        var provisioned = await provisioner.ProvisionModuleClientAsync("documents", Ct);
        Assert.True(provisioned.IsSuccess, provisioned.Error?.ToString());
        Assert.Equal("documents", provisioned.Value.ClientId);
        Assert.NotEmpty(provisioned.Value.Secret);
        var client = (await catalog.GetClientAsync("documents", Ct)).Value;
        Assert.Equal(ClientKind.Confidential, client.Kind);
        Assert.Equal(["documents"], client.Scopes);
        var documents = (await catalog.GetScopeAsync("documents", Ct)).Value;
        Assert.Equal(["documents"], documents.Resources);

        Assert.Equal(IssuerErrors.ClientExistsCode, (await provisioner.ProvisionModuleClientAsync("documents", Ct)).Error?.Code);
        Assert.Equal(IssuerErrors.ClientInvalidCode, (await provisioner.ProvisionModuleClientAsync("Not-A-Module", Ct)).Error?.Code);

        var rotated = await provisioner.RotateSecretAsync("documents", Ct);
        Assert.True(rotated.IsSuccess);
        Assert.NotEqual(provisioned.Value.Secret, rotated.Value.Secret);
        Assert.Equal(System.Net.HttpStatusCode.Unauthorized, (await app.ClientCredentialsAsync("documents", provisioned.Value.Secret, "documents", Ct)).Status);
        Assert.Equal(System.Net.HttpStatusCode.OK, (await app.ClientCredentialsAsync("documents", rotated.Value.Secret, "documents", Ct)).Status);
        Assert.Equal(IssuerErrors.ClientNotFoundCode, (await provisioner.RotateSecretAsync("nowhere", Ct)).Error?.Code);

        await provisioner.DeprovisionModuleClientAsync("documents", Ct);
        Assert.Equal(IssuerErrors.ClientNotFoundCode, (await catalog.GetClientAsync("documents", Ct)).Error?.Code);
        Assert.Equal(IssuerErrors.ScopeNotFoundCode, (await catalog.GetScopeAsync("documents", Ct)).Error?.Code);
        await provisioner.DeprovisionModuleClientAsync("documents", Ct);   // nothing to do, no error
    }

    [Fact]
    public async Task Clients_and_scopes_are_created_read_changed_and_deleted_and_a_secret_is_never_read_back()
    {
        await using var app = await IssuerTestHost.Builder().StartAsync(Ct);
        using var scope = app.Services.CreateScope();
        var catalog = scope.ServiceProvider.GetRequiredService<IssuerCatalog>();

        Assert.True((await catalog.CreateScopeAsync(new ScopeDefinition("documents", "Documents", "Read and write documents"), Ct)).IsSuccess);
        Assert.Equal(IssuerErrors.ScopeExistsCode, (await catalog.CreateScopeAsync(new ScopeDefinition("documents"), Ct)).Error?.Code);
        Assert.Equal(IssuerErrors.ScopeInvalidCode, (await catalog.CreateScopeAsync(new ScopeDefinition("Docs!"), Ct)).Error?.Code);
        var updated = await catalog.UpdateScopeAsync(new ScopeDefinition("documents", Resources: ["documents", "rendering"]), Ct);
        Assert.Equal(["documents", "rendering"], updated.Value.Resources);

        var created = await catalog.CreateClientAsync(new ClientDefinition("desktop", "The desktop client", ClientKind.Public, ["openid", "documents"], [IssuerTestHost.RedirectUri]), Ct);
        Assert.True(created.IsSuccess, created.Error?.ToString());
        Assert.Null(created.Value.Secret);
        Assert.Equal(["documents"], created.Value.Client.Scopes);           // openid needs no permission
        Assert.Equal([IssuerTestHost.RedirectUri], created.Value.Client.RedirectUris);
        Assert.Equal(IssuerErrors.ClientExistsCode, (await catalog.CreateClientAsync(new ClientDefinition("desktop"), Ct)).Error?.Code);
        Assert.Equal(IssuerErrors.ClientInvalidCode, (await catalog.CreateClientAsync(new ClientDefinition("desktop", Secret: "x"), Ct)).Error?.Code);
        Assert.Equal(IssuerErrors.ClientInvalidCode, (await catalog.CreateClientAsync(new ClientDefinition("bad client"), Ct)).Error?.Code);
        Assert.Equal(IssuerErrors.ClientInvalidCode, (await catalog.CreateClientAsync(new ClientDefinition("web", RedirectUris: ["relative/path"]), Ct)).Error?.Code);

        var service = await catalog.CreateClientAsync(new ClientDefinition("reporting", Kind: ClientKind.Confidential, Scopes: ["documents"]), Ct);
        Assert.True(service.IsSuccess);
        Assert.NotNull(service.Value.Secret);                                 // generated, shown once
        var kept = await catalog.UpdateClientAsync(new ClientDefinition("reporting", "Reporting", ClientKind.Confidential, ["documents"]), Ct);
        Assert.Null(kept.Value.Secret);                                      // the secret is kept, not regenerated, not shown
        Assert.Equal(System.Net.HttpStatusCode.OK, (await app.ClientCredentialsAsync("reporting", service.Value.Secret!, "documents", Ct)).Status);
        Assert.Equal("Reporting", (await catalog.GetClientAsync("reporting", Ct)).Value.DisplayName);

        Assert.Equal(["desktop", "reporting"], (await catalog.ListClientsAsync(Ct)).Select(client => client.ClientId));
        Assert.Equal(["documents"], (await catalog.ListScopesAsync(Ct)).Select(scope => scope.Name));
        Assert.True((await catalog.DeleteClientAsync("desktop", Ct)).IsSuccess);
        Assert.Equal(IssuerErrors.ClientNotFoundCode, (await catalog.DeleteClientAsync("desktop", Ct)).Error?.Code);
        Assert.True((await catalog.DeleteScopeAsync("documents", Ct)).IsSuccess);
        Assert.Equal(IssuerErrors.ScopeNotFoundCode, (await catalog.DeleteScopeAsync("documents", Ct)).Error?.Code);
    }

    [Fact]
    public async Task What_the_environment_configures_of_a_client_overlays_its_declaration_and_is_re_applied_on_demand()
    {
        await using var app = await IssuerTestHost.Builder(options =>
        {
            options.Clients["desktop"] = new ConfiguredClientOptions { RedirectUris = ["http://127.0.0.1:7000/"] };
            options.Clients["reporting"] = new ConfiguredClientOptions { Secret = "configured-secret" };
            options.Clients["nowhere"] = new ConfiguredClientOptions { Secret = "unused" };
        }).StartAsync(Ct);
        using var scope = app.Services.CreateScope();
        var catalog = scope.ServiceProvider.GetRequiredService<IssuerCatalog>();
        Assert.True((await catalog.CreateScopeAsync(new ScopeDefinition("documents"), Ct)).IsSuccess);

        var desktop = await catalog.CreateClientAsync(new ClientDefinition("desktop", Scopes: ["documents"]), Ct);
        Assert.Equal(["http://127.0.0.1:7000/"], desktop.Value.Client.RedirectUris);   // from the configuration, the declaration being silent
        var reporting = await catalog.CreateClientAsync(new ClientDefinition("reporting", Kind: ClientKind.Confidential, Scopes: ["documents"]), Ct);
        Assert.Null(reporting.Value.Secret);                                 // the configured secret, nothing generated
        Assert.Equal(System.Net.HttpStatusCode.OK, (await app.ClientCredentialsAsync("reporting", "configured-secret", "documents", Ct)).Status);

        var explicitRedirect = await catalog.UpdateClientAsync(new ClientDefinition("desktop", Scopes: ["documents"], RedirectUris: ["http://127.0.0.1:7001/"]), Ct);
        Assert.Equal(["http://127.0.0.1:7001/"], explicitRedirect.Value.Client.RedirectUris);   // the declaration wins when it speaks

        var applied = await catalog.ApplyConfiguredClientsAsync(Ct);
        Assert.Equal(["desktop", "reporting"], applied.Order(StringComparer.Ordinal));          // the client nowhere is skipped
        Assert.Equal(["http://127.0.0.1:7000/"], (await catalog.GetClientAsync("desktop", Ct)).Value.RedirectUris);
    }
}
