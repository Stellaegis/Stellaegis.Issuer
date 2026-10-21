# Stellaegis.Issuer

Stellaegis.Issuer is the OpenID Connect issuer of a .NET application assembled on
[Stellaegis.Primitives](https://github.com/Stellaegis/Stellaegis.Primitives): it turns a person the host has
authenticated into tokens, gives the services their credentials, holds the clients and the scopes, revokes, and
gives every resource server what it needs to accept a bearer token and refuse a revoked one. It is built on
[OpenIddict](https://github.com/openiddict/openiddict-core).

It knows no account. The person comes to it already signed in — by the cookie of
[Stellaegis.Identity](https://github.com/Stellaegis/Stellaegis.Identity), by Negotiate, by whatever the host
authenticates with — and the one question it asks of the accounts, *is this person still admitted?*, goes through
the admission of Primitives, which the accounts answer. And it decides no right: that is `Stellaegis.Access`. The
issuer executes; what an API is and who a client belongs to is the registry's to say.

The library targets .NET 10 and is released under the MIT license.

## Packages

| Package | Contents | Depends on |
| --- | --- | --- |
| `Stellaegis.Issuer` | The issuer: OpenIddict as the server — authorization code with PKCE, client credentials, refresh tokens —, the protocol routes, the catalog of clients and scopes, the provisioning of a module's credentials, the revocation, the administration routes, the module and its operations, the event | `Stellaegis.Issuer.Client`, `Stellaegis.Primitives.AspNetCore`, OpenIddict, EF Core |
| `Stellaegis.Issuer.PostgreSQL` | The stores on PostgreSQL, and the `oidc` schema declared as a module database for the installation and the verification | `Stellaegis.Primitives.Data`, the Npgsql provider of EF Core |
| `Stellaegis.Issuer.Client` | What a host that is not the issuer takes: the validation of the bearer tokens, the admission of the revoked tokens, the credentials a service speaks with. No OpenIddict | `Stellaegis.Primitives.AspNetCore`, JwtBearer |
| `Stellaegis.Issuer.Server` | The sessions page a person ends their sessions on, as a Razor class library the host mounts beside the pages of the accounts | `Stellaegis.Issuer`, ASP.NET Core |

The four packages share one version, and follow the major version of Stellaegis.Primitives: 5.0.0 runs on
Primitives 5.1.0.

## Two hosts, in full

A service apart from the host that issues the tokens: this is `samples/`, which runs as is on a PostgreSQL server
and whose [README](samples/README.md) plays the native flow by hand.

The first host holds the accounts and the issuer — one process, one compartment, the company itself:

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddStellaegisFrame(ApplicationFrame.SingleCompartment("acme"));
builder.Services.AddStellaegisRequestContext();

builder.Services.AddStellaegisIdentityPostgreSQL(builder.Configuration);   // the accounts, Stellaegis.Identity
builder.Services.AddStellaegisIdentityCookie();
builder.Services.AddStellaegisIdentityPages(builder.Configuration);
builder.Services.AddStellaegisIdentityAdministration();
builder.Services.AddStellaegisLocalBlockedUsersSource();
builder.Services.AddStellaegisIdentityAdmission(builder.Configuration);

builder.Services.AddStellaegisIssuerPostgreSQL(builder.Configuration);     // Stellaegis:Issuer:PostgreSQL, Stellaegis:Issuer
builder.Services.AddStellaegisIssuerAdministration();
builder.Services.AddStellaegisIssuerAdmission(builder.Configuration);      // Stellaegis:Issuer:Admission — the revoked tokens, from its own store
builder.Services.AddStellaegisIssuerPages(builder.Configuration);          // Stellaegis:Issuer:Pages — /account/sessions

builder.Services.AddStellaegisBearer(builder.Configuration);               // Stellaegis:Issuer:Bearer — its own administration routes, called by the services
builder.Services.AddAuthentication(o => o.DefaultScheme = "Sample")        // a bearer token names the bearer, anything else the cookie
    .AddPolicyScheme("Sample", "Sample", scheme => scheme.ForwardDefaultSelector = context =>
        context.Request.Headers.Authorization.ToString().StartsWith("Bearer ") ? JwtBearerDefaults.AuthenticationScheme : IdentityCookie.Scheme);

builder.Services.AddSingleton<IIdentityMailer, MyMailer>();
builder.Services.AddSingleton<IEventPublisher, MyBus>();                   // UserBlocked → BlockedAccounts.Block, ITokenRevoker.RevokeSubjectAsync
builder.Services.AddAuthorization(options => { /* one policy per operation of IdentityOperations.All and IssuerOperations.All */ });

var app = builder.Build();
await app.Services.VerifyStellaegisDatabasesAsync();   // ident and oidc were installed before, under another role: prove it

app.MapStaticAssets();
app.UseAuthentication();
app.UseWhen(c => !c.Request.Path.StartsWithSegments("/connect"), door => door.UseStellaegisActorAdmission());
app.UseAuthorization();

app.MapStellaegisIdentityPages();                      // /login, /account/…, and /account/sessions among them
app.MapStellaegisIssuer();                             // /connect/authorize, /connect/logout; /connect/token is OpenIddict's own
app.MapGroup("/api/admin").MapIdentityAdminEndpoints().RequireAuthorizationPerOperation(op => op.ToString());
app.MapGroup("/api/admin").MapIssuerAdminEndpoints().RequireAuthorizationPerOperation(op => op.ToString());

app.Run();
```

The second host is a resource server, on `Stellaegis.Issuer.Client` alone:

```csharp
builder.Services.AddStellaegisFrame(ApplicationFrame.SingleCompartment("acme"));
builder.Services.AddStellaegisRequestContext();                            // the actor is the sub of the token
builder.Services.AddStellaegisModule(InventoryModule.Declaration);

builder.Services.AddStellaegisBearer(builder.Configuration);               // Stellaegis:Issuer:Bearer — the issuer as authority, this host's module as audience
builder.Services.AddStellaegisIssuerM2M(builder.Configuration);            // Stellaegis:Issuer:M2M — this host's own credentials
builder.Services.AddStellaegisIssuerClient(builder.Configuration);         // Stellaegis:Issuer:Client — where the revoked tokens are read
builder.Services.AddStellaegisIssuerAdmission(builder.Configuration);      // Stellaegis:Issuer:Admission — read at startup, then periodically

var app = builder.Build();
app.UseAuthentication();
app.UseStellaegisActorAdmission();
app.UseAuthorization();
app.MapGroup("/api").MapInventoryEndpoints().RequireAuthorizationPerOperation(op => op.ToString());
app.Run();
```

What the host brings is its own: its modules, its rights system answering the policies named after the
operations, its bus behind `IEventPublisher`, the accounts it authenticates with.

## Installing, then verifying

The issuer lives in the schema `oidc` of a PostgreSQL database: four tables, `applications`, `authorizations`,
`scopes`, `tokens`, the OpenIddict model. Two executants, two roles, as everywhere in the family: an installer
installs, under a role that owns the schema; the application verifies at every startup, under its own role, which
was granted its data rights and never a DDL right.

```csharp
await DatabaseLifecycle.InstallAsync([IdentityDatabase.Value, IssuerDatabase.Value], frame, openAsAdministrator, applicationRole: "myapp_app");
```

The script of the schema is the DDL of the EF Core model of the OpenIddict stores, generated once from the model
on the Npgsql provider and frozen in the package: EF Core reads and writes these tables at run time and never
creates nor migrates them — a test proves the model reads what the script installed, and that no migration
exists. The installation records each script with its checksum and is replayable; the application then verifies —
`AddStellaegisDatabaseVerification()` in a generic host, `app.Services.VerifyStellaegisDatabasesAsync()` in an
ASP.NET Core host — and refuses to start when the schema is not installed, or not as the package declares it.

No client is seeded, no scope. What exists is what the installation declared, as the example's `install` verb
does, through the services of the module: the credentials of each service, the native client of the desktop, and
what the environment adds to them.

```sh
dotnet run -- install --admin-email admin@acme.test --admin-password 'Correct-Horse-9'
```

## The flows

Three, as OpenIddict serves them on `/connect/token`, with PKCE required of every public client:

| Flow | Who | What the token carries |
| --- | --- | --- |
| Authorization code with PKCE, then refresh | a person, through a browser or a native application | `sub` the person's id, `email`; `name` in the identity token only; the scopes requested; as audiences the resources of those scopes |
| Client credentials | a service, with the secret the installation gave it | `sub` the client id; the scopes requested, and their resources as audiences |

The token is compact: `sub`, `email`, scopes, audiences, nothing else — no tenant, no permission; the rights are
decided at every call, by `Stellaegis.Access`, so that revoking one is immediate. A scope is the name of a module,
and the audience of a token carrying it is the same name: a resource server accepts the tokens of its modules.

`/connect/authorize` takes a person **the host has authenticated**: a stranger is challenged on the host's scheme
— `AuthenticationScheme` in the options, or the host's default — and comes back signed in; a person signed in is
first asked of every `IActorAdmission` registered — a blocked account is refused there, whatever the cookie says —,
a refusal signs them out and sends the client `access_denied` with the reason. The refresh asks the admissions
again, and answers `invalid_grant` when they refuse. The routes are Minimal API: the host maps them with
`MapStellaegisIssuer()`, after `UseAuthentication()`, and needs no MVC.

⚠ The door of Primitives, `UseStellaegisActorAdmission()`, refuses a blocked person with 401 before the
authorization route can answer the client: a host that holds the issuer beside its resource routes enables the
door on the resource routes — `app.UseWhen(c => !c.Request.Path.StartsWithSegments("/connect"), door => door.UseStellaegisActorAdmission())`
—, or accepts the 401. Either way nothing is issued to a refused person.

### Options

```text
Stellaegis:Issuer:Issuer                          the issuer URI advertised and carried by every token; derived from the request unless set
Stellaegis:Issuer:AccessTokenLifetime              00:10:00; IdentityTokenLifetime 00:10:00; AuthorizationCodeLifetime 00:05:00; RefreshTokenLifetime 30.00:00:00
Stellaegis:Issuer:EncryptAccessTokens              true: JWE, read by a resource server holding the encryption key; false: JWS, validated by any resource server
Stellaegis:Issuer:RequireHttps                     true; a development host behind plain HTTP sets false
Stellaegis:Issuer:AuthenticationScheme             the scheme the authorization route challenges and reads a person from; the host's default unless set
Stellaegis:Issuer:TokenRateLimitingPolicy          the name of a rate-limiting policy of the host, applied to /connect/token
Stellaegis:Issuer:StandardScopes                   email, profile; openid and offline_access are always known
Stellaegis:Issuer:Certificates:UseDevelopmentCertificates   Development only — see below
Stellaegis:Issuer:Certificates:Signing:Path        a PKCS #12 file, with Password; or Thumbprint, in the current user's store
Stellaegis:Issuer:Certificates:Encryption:Path     the same, for the encryption; required when EncryptAccessTokens holds
Stellaegis:Issuer:Clients:{clientId}:Secret        what the environment adds to a client the installation declared
Stellaegis:Issuer:Clients:{clientId}:RedirectUris  idem; PostLogoutRedirectUris
Stellaegis:Issuer:PostgreSQL:ConnectionString      the application's connection, read at registration; empty, the registration refuses
```

Every option is validated when the host starts. Outside the `Development` environment, the development
certificates are refused — every restart would renew them and invalidate every token issued — and a signing
certificate is required, an encryption one too when the access tokens are encrypted.

### The clients and the scopes

`IssuerCatalog` is what the installation declares with and the administration reads and changes: clients and
scopes, nothing of its own. A client is **public** — a browser application, its redirect URIs matched exactly —,
**native** — a desktop or mobile application, public too, whose redirect URI on the loopback,
`http://127.0.0.1/callback`, is matched whatever the port the application listens on (RFC 8252 § 7.3) —, or
**confidential** — a service, with a secret. A secret is given at creation or regenerated; it is never read back.
What is specific to an environment — a secret, the redirect URIs — may be left out of the declaration: the catalog
then takes it from `Stellaegis:Issuer:Clients`, and `ApplyConfiguredClientsAsync()` re-applies it to the clients
already declared, which the installation calls after a configuration changed.

`IOidcClientProvisioner` gives a module its credentials to speak as itself: a confidential client whose id is the
module's name, and the scope of the same name whose resource is the module. The installation calls it when it
declares a module's API; in the SaaS, the tenancy does; the registry never does.

## The administration routes

`MapIssuerAdminEndpoints()` maps the administration of the issuer, relative to the group it is called on, under
`issuer`. The module has no compartment: its routes read no request context. A client or a scope is nobody's
resource, so the routes declare they load none: the operation each is labelled with is the whole decision, and the
host declares who may call it. `AddStellaegisIssuerAdministration()` registers the startup check of Primitives
that refuses a route left without authorization.

| Route | Operation |
| --- | --- |
| `GET issuer/clients`, `GET issuer/clients/{clientId}` | `clients.read` |
| `POST issuer/clients`, `PUT issuer/clients/{clientId}`, `POST issuer/clients/{clientId}/rotate-secret`, `POST issuer/apis/{module}`, `POST issuer/apis/{module}/rotate-secret` | `clients.write` |
| `DELETE issuer/clients/{clientId}`, `DELETE issuer/apis/{module}` | `clients.delete` |
| `GET issuer/scopes`, `GET issuer/scopes/{name}` | `scopes.read` |
| `POST issuer/scopes`, `PUT issuer/scopes/{name}` | `scopes.write` |
| `DELETE issuer/scopes/{name}` | `scopes.delete` |
| `POST issuer/subjects/{subject}/revoke`, `POST issuer/authorizations/{id}/revoke`, `POST issuer/tokens/{id}/revoke`, `GET issuer/security/revoked-tokens` | `tokens.revoke` |

Provisioning a module is writing a client: no operation of its own. The module declares these seven operations,
`IssuerOperations.All`, so that the startup check refuses a route labelled with one the module does not declare,
and so that a host harvests its catalogue from the declarations. The routes carry no name, so the module can be
mapped several times in one host.

## Revocation and admission

`ITokenRevoker` revokes what the issuer issued — every token of a subject, a session (an authorization and its
tokens), one token — at the store, and announces each access token revoked before its expiration as a
`TokenRevokedEvent` on the `IEventPublisher` of Primitives: `TokenId`, `Subject`, `ExpiresAt`. The caller owns the
decision: the host calls it from its subscription to the `UserBlocked` event of the accounts, an administrator from
the `tokens.revoke` routes, the person from their sessions page. The module subscribes to nothing.

A resource server refuses a revoked token at the door, before any route runs, with the admission of Primitives:
`AddStellaegisIssuerAdmission()` keeps the revoked tokens in memory, read from `IRevokedTokensSource` when the host
starts and then every `Stellaegis:Issuer:Admission:ReconcileInterval` (two minutes unless set; zero for a single
reading), and registers them as the `IActorAdmission` of the issuer — beside the one of the accounts, for the
blocked ones. `UseStellaegisActorAdmission()` of Primitives, after `UseAuthentication()`, asks every admission and
answers 401 with the code of the first refusal, `Token.Revoked` here. The source is the issuer's own store on the
host that holds it; on a resource server apart, `AddStellaegisIssuerClient` registers the HTTP source, which reads
`GET issuer/security/revoked-tokens` with the token an `IIssuerClientTokenProvider` gives — `AddStellaegisIssuerM2M`
registers one over the host's own credentials, for the scope `issuer`, which the installation grants to every
service that reads the issuer. A revocation applies without waiting for the next reading when the host connects
its bus: on `TokenRevoked`, call `RevokedTokens.Revoke(tokenId, expiresAt)`; the host that holds the issuer does it
by itself.

## A resource server

`AddStellaegisBearer` registers the JWT bearer authentication of the tokens the issuer issued, as the default
scheme of the host: the issuer as authority, read through its discovery document; the audiences this host serves,
which are the names of its modules; the claims kept as the token names them, `sub` and `scope`, not their
WS-Federation renames; the scopes split into one `scope` claim each, for a policy that requires one.

```text
Stellaegis:Issuer:Bearer:Authority = https://id.acme.example
Stellaegis:Issuer:Bearer:Audiences:0 = inventory
Stellaegis:Issuer:Bearer:RequireHttpsMetadata = true; ClockSkew = 00:05:00; MetadataAddress when not at the authority's well-known path
Stellaegis:Issuer:Bearer:Decryption:Path = …          the encryption certificate, when the issuer encrypts (JWE)
```

A host that authenticates with several schemes — the cookie of the accounts beside the bearer — chooses between
them with a policy scheme of its own, after this call, as the first host of the example does.

**Encrypted tokens and hosts apart.** The issuer encrypts its access tokens unless told otherwise (JWE). An
encrypted token is read by nobody but a resource server holding the encryption certificate's private key, named
in `Decryption`. Sharing a private key across hosts is a deployment of its own: in a distributed topology, the
issuer sets `EncryptAccessTokens = false`, and the token — signed, validated by any resource server with the public
keys of the discovery document — stays compact, with nothing in it worth hiding. A single host that holds the
issuer and its resource routes keeps the encryption and decrypts with the same certificate. A test proves both: a
server with the key reads the JWE, one without refuses it.

**The credentials of a service.** `M2MTokenProvider` obtains a token by the `client_credentials` grant for the
scope asked — the name of the module called — and keeps it for 80 % of its lifetime. `M2MTokenHandler` attaches
it to every request of an HTTP client; `AddM2MToken(scope)` puts the handler on a client being built:

```text
Stellaegis:Issuer:M2M:Authority = https://id.acme.example
Stellaegis:Issuer:M2M:ClientId = inventory
Stellaegis:Issuer:M2M:ClientSecret = …                                    (from a secret store)
```

```csharp
builder.Services.AddStellaegisHttpClient<IDocumentsClient, HttpDocumentsClient, DocumentsClientOptions>(builder.Configuration, "Stellaegis:Documents:Client")
    .AddM2MToken("documents");
```

A host that reads the blocked accounts of `Stellaegis.Identity` over HTTP gives its client the same credentials
in one line, an `IIdentityClientTokenProvider` over `M2MTokenProvider`: this package does not reference Identity,
the host connects the two.

## A native client

A desktop or mobile application signs in the way the standard says (RFC 8252): it opens the **system browser** on
`/connect/authorize` with a PKCE challenge, the person signs in on the pages of the accounts — the second factor
included —, the browser comes back to a loopback address the application listens on, with a code, and the
application exchanges the code with its verifier on `/connect/token`. One login page for every client; the
password never passes through the application; with Negotiate, the browser signs in silently. The client is
declared *native*, its redirect URI `http://127.0.0.1/callback`, and it listens on whatever port is free. The
`samples/` README plays the flow by hand; `IdentityModel.OidcClient` does it in a .NET application.

## The sessions page

`Stellaegis.Issuer.Server` is a Razor class library with one page, `/account/sessions`: the applications signed
in on the person's behalf — one per authorization that still holds an access or a refresh token —, each one to end,
or all at once, which signs the person out of the host. The host mounts it beside the pages of the accounts:

```csharp
builder.Services.AddStellaegisIssuerPages(builder.Configuration);   // Stellaegis:Issuer:Pages
...
app.MapStaticAssets();
app.MapStellaegisIssuerPages();                                     // the host's MapRazorPages; MapStellaegisIdentityPages() maps it too
```

The page renders inside `_AccountLayout` when the host, or `Stellaegis.Identity.Server`, provides one — it then
sits among the account pages, and the host adds the link to it in its own `Pages/Shared/_AccountLayout.cshtml`, as
the example does —, inside the package's own layout otherwise. It is made the host's own the way the pages of the
accounts are: the options — `ApplicationName`, `Culture`, `StylesheetPath`, `RateLimitingPolicy`,
`AfterRevokeAllPath` —, the texts per culture in `Texts`, a stylesheet on the same CSS variables as the pages of the
accounts, a file of the host at the same path. The texts come in English and in French.

## Events

The module publishes one event through the `IEventPublisher` of Primitives, `TokenRevokedEvent`, a record
implementing `IEvent`, to whatever bus the host registered and nowhere when it registered none; it subscribes to
nothing.

## Tests

```powershell
$env:STELLAEGIS_TEST_POSTGRESQL = "Host=127.0.0.1;Username=postgres;Database=postgres"
dotnet test --solution Stellaegis.Issuer.slnx
```

The flows, the revocation, the catalog, the routes, the sessions page and a resource server apart run on the test
server over SQLite in memory. The PostgreSQL tests create the database `stellaegis_issuer_tests` on that server if
it does not exist, install the schema as an installer does, under that connection, and run under an ordinary role
they create, `stellaegis_issuer_app`. Without the variable they are skipped. The publishing workflow runs them
against a PostgreSQL service and fails on a skipped test.

## License

MIT — see [LICENSE](https://github.com/Stellaegis/Stellaegis.Issuer/blob/main/LICENSE). The packages depend on
OpenIddict (Apache-2.0) and the components listed in
[THIRD-PARTY-NOTICES.md](https://github.com/Stellaegis/Stellaegis.Issuer/blob/main/THIRD-PARTY-NOTICES.md).
