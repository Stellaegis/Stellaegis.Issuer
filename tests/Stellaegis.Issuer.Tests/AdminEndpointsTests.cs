using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Stellaegis.Issuer.Client;

namespace Stellaegis.Issuer.Tests;

/// <summary>The administration routes, under the operations a host grants.</summary>
public sealed class AdminEndpointsTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task An_administrator_holding_the_operations_runs_the_life_of_the_clients_and_the_scopes()
    {
        await using var app = await IssuerTestHost.Builder().StartAsync(Ct);
        var client = app.ClientHolding("admin", IssuerTestHost.Everything);

        var scope = await client.PostAsJsonAsync("/api/admin/issuer/scopes", new ScopeDefinition("documents", "Documents"), Ct);
        Assert.Equal(HttpStatusCode.Created, scope.StatusCode);
        Assert.Equal(["documents"], (await scope.Content.ReadFromJsonAsync<OidcScope>(Ct))!.Resources);
        Assert.Equal(HttpStatusCode.Conflict, (await client.PostAsJsonAsync("/api/admin/issuer/scopes", new ScopeDefinition("documents"), Ct)).StatusCode);
        var changed = await client.PutAsJsonAsync("/api/admin/issuer/scopes/documents", new ScopeDefinition("documents", Resources: ["documents", "rendering"]), Ct);
        Assert.Equal(HttpStatusCode.OK, changed.StatusCode);
        Assert.Equal(["documents", "rendering"], (await changed.Content.ReadFromJsonAsync<OidcScope>(Ct))!.Resources);
        var mismatch = await client.PutAsJsonAsync("/api/admin/issuer/scopes/documents", new ScopeDefinition("rendering"), Ct);
        Assert.Equal(HttpStatusCode.BadRequest, mismatch.StatusCode);
        Assert.Equal(IssuerErrors.ScopeInvalidCode, await mismatch.CodeOfAsync(Ct));
        Assert.Single((await client.GetFromJsonAsync<OidcScope[]>("/api/admin/issuer/scopes", Ct))!);

        var created = await client.PostAsJsonAsync("/api/admin/issuer/clients", new ClientDefinition("desktop", "The desktop", ClientKind.Public, ["documents"], [IssuerTestHost.RedirectUri]), Ct);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var saved = (await created.Content.ReadFromJsonAsync<ClientSaved>(Ct))!;
        Assert.Equal(ClientKind.Public, saved.Client.Kind);
        Assert.Null(saved.Secret);
        Assert.Equal(HttpStatusCode.Conflict, (await client.PostAsJsonAsync("/api/admin/issuer/clients", new ClientDefinition("desktop"), Ct)).StatusCode);

        var one = await client.GetFromJsonAsync<OidcClient>("/api/admin/issuer/clients/desktop", Ct);
        Assert.Equal("The desktop", one!.DisplayName);
        Assert.Equal(["documents"], one.Scopes);
        var renamed = await client.PutAsJsonAsync("/api/admin/issuer/clients/desktop", new ClientDefinition("", "The renamed desktop", ClientKind.Public, ["documents"], [IssuerTestHost.RedirectUri]), Ct);
        Assert.Equal(HttpStatusCode.OK, renamed.StatusCode);
        Assert.Equal("The renamed desktop", (await renamed.Content.ReadFromJsonAsync<ClientSaved>(Ct))!.Client.DisplayName);
        Assert.Single((await client.GetFromJsonAsync<OidcClient[]>("/api/admin/issuer/clients", Ct))!);

        Assert.Equal(HttpStatusCode.NoContent, (await client.DeleteAsync("/api/admin/issuer/clients/desktop", Ct)).StatusCode);
        var gone = await client.GetAsync("/api/admin/issuer/clients/desktop", Ct);
        Assert.Equal(HttpStatusCode.NotFound, gone.StatusCode);
        Assert.Equal(IssuerErrors.ClientNotFoundCode, await gone.CodeOfAsync(Ct));
        Assert.Equal(HttpStatusCode.NoContent, (await client.DeleteAsync("/api/admin/issuer/scopes/documents", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.DeleteAsync("/api/admin/issuer/scopes/documents", Ct)).StatusCode);
    }

    [Fact]
    public async Task A_secret_is_shown_once_at_creation_and_at_rotation_and_never_read_back()
    {
        await using var app = await IssuerTestHost.Builder().StartAsync(Ct);
        var client = app.ClientHolding("admin", IssuerTestHost.Everything);
        Assert.Equal(HttpStatusCode.Created, (await client.PostAsJsonAsync("/api/admin/issuer/scopes", new ScopeDefinition("documents"), Ct)).StatusCode);

        var created = await client.PostAsJsonAsync("/api/admin/issuer/clients", new ClientDefinition("worker", Kind: ClientKind.Confidential, Scopes: ["documents"]), Ct);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var saved = (await created.Content.ReadFromJsonAsync<ClientSaved>(Ct))!;
        Assert.NotNull(saved.Secret);
        Assert.NotEmpty(saved.Secret);

        var read = await client.GetAsync("/api/admin/issuer/clients/worker", Ct);
        var body = await read.Content.ReadFromJsonAsync<JsonElement>(Ct);
        Assert.False(body.TryGetProperty("secret", out _));
        Assert.DoesNotContain(saved.Secret, await read.Content.ReadAsStringAsync(Ct));

        var rotated = await client.PostAsync("/api/admin/issuer/clients/worker/rotate-secret", null, Ct);
        Assert.Equal(HttpStatusCode.OK, rotated.StatusCode);
        var secret = (await rotated.Content.ReadFromJsonAsync<ProvisionedClient>(Ct))!.Secret;
        Assert.NotEqual(saved.Secret, secret);
        Assert.Equal(HttpStatusCode.Unauthorized, (await app.ClientCredentialsAsync("worker", saved.Secret, "documents", Ct)).Status);

        var provisioned = await client.PostAsync("/api/admin/issuer/apis/rendering", null, Ct);
        Assert.Equal(HttpStatusCode.Created, provisioned.StatusCode);
        var module = (await provisioned.Content.ReadFromJsonAsync<ProvisionedClient>(Ct))!;
        Assert.Equal("rendering", module.ClientId);
        Assert.Equal(HttpStatusCode.OK, (await app.ClientCredentialsAsync("rendering", module.Secret, "rendering", Ct)).Status);
        Assert.Equal(HttpStatusCode.Conflict, (await client.PostAsync("/api/admin/issuer/apis/rendering", null, Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsync("/api/admin/issuer/apis/rendering/rotate-secret", null, Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await client.DeleteAsync("/api/admin/issuer/apis/rendering", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/api/admin/issuer/scopes/rendering", Ct)).StatusCode);
    }

    [Fact]
    public async Task Revoking_from_the_routes_and_reading_the_revoked_tokens()
    {
        await using var app = await IssuerTestHost.Builder().StartAsync(Ct);
        await app.DeclarePublicClientAsync(ct: Ct);
        var (code, verifier) = await app.AuthorizeAsync("jane", ct: Ct);
        var tokens = await app.ExchangeCodeAsync(code, verifier, ct: Ct);
        var tokenId = IssuerTestHost.Payload(tokens.AccessToken).GetProperty(RevokedTokens.TokenIdClaim).GetString()!;
        var client = app.ClientHolding("admin", IssuerTestHost.Everything);

        Assert.Empty((await client.GetFromJsonAsync<RevokedToken[]>("/api/admin/issuer/security/revoked-tokens", Ct))!);
        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsync($"/api/admin/issuer/tokens/{tokenId}/revoke", null, Ct)).StatusCode);
        Assert.Equal(tokenId, Assert.Single((await client.GetFromJsonAsync<RevokedToken[]>("/api/admin/issuer/security/revoked-tokens", Ct))!).TokenId);
        Assert.Equal(HttpStatusCode.NotFound, (await client.PostAsync("/api/admin/issuer/tokens/nowhere/revoke", null, Ct)).StatusCode);

        var revoked = await client.PostAsync("/api/admin/issuer/subjects/jane/revoke", null, Ct);
        Assert.Equal(HttpStatusCode.OK, revoked.StatusCode);
        Assert.True((await revoked.Content.ReadFromJsonAsync<Revoked>(Ct))!.Count >= 1);          // the refresh token, the access one being revoked already
        Assert.Equal("invalid_grant", (await app.RefreshAsync(tokens.RefreshToken, ct: Ct)).Error);
        Assert.Equal(HttpStatusCode.NotFound, (await client.PostAsync("/api/admin/issuer/authorizations/nowhere/revoke", null, Ct)).StatusCode);
    }

    [Fact]
    public async Task A_route_refuses_a_caller_without_its_operation_and_an_anonymous_one()
    {
        await using var app = await IssuerTestHost.Builder().StartAsync(Ct);

        var reader = app.ClientHolding("reader", IssuerOperations.ClientsRead.ToString());
        Assert.Equal(HttpStatusCode.OK, (await reader.GetAsync("/api/admin/issuer/clients", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await reader.PostAsJsonAsync("/api/admin/issuer/clients", new ClientDefinition("desktop"), Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await reader.GetAsync("/api/admin/issuer/scopes", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await reader.GetAsync("/api/admin/issuer/security/revoked-tokens", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await app.GetTestClient().GetAsync("/api/admin/issuer/clients", Ct)).StatusCode);
    }

    [Fact]
    public async Task The_routes_mapped_without_authorization_fail_the_startup()
    {
        var builder = IssuerTestHost.Builder();
        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapIssuerAdminEndpoints();

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => app.StartAsync(Ct));

        Assert.Contains("authorization", exception.Message, StringComparison.OrdinalIgnoreCase);
    }
}
