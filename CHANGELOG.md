# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [5.4.0] — 2026-10-28

What the application asks of the login. The authorization served any open session without a page, whatever the
request said: an application could not have the login asked again, nor know when it was done.

### Added

- **`prompt` and `max_age`**, OpenID Connect Core § 3.1.2.1: `login` and a `max_age` the login is older than sign the
  session out and ask the login; `select_account` shows the open session on the login page; `none` answers or says
  `login_required`.
- **`auth_time`** in the access and the identity tokens, as a number, copied from the host's session;
  `Stellaegis.Identity` 6.3.0 writes it. A refresh keeps the login's.
- **`ClientPrompt`**, `ClientDefinition.Prompt` and `OidcClient.Prompt`: what the authorization asks of the login for
  a client whose request says nothing — `Silent`, `SelectAccount`, `Login` —, kept in the properties of its
  application, with no schema change.
- **`stellaegis_prompted`**, `IssuerEndpoints.PromptedParameter`: the mark of the way back from the login, protected
  and bound to its request. `AddStellaegisIssuer` registers the data protection.

### Changed

- The example host takes `Stellaegis.Identity` 6.3.0 and declares `AvatarUrl`: `picture` and `auth_time` in its tokens.

### Updating from 5.3.0

1. **Nothing to install**: the schema is unchanged.
2. **A request with `prompt=login` or `max_age`**, which was answered without a page, now asks the login.
3. **Several instances of a host** share their data-protection keys, or a way back from the login reaching another
   instance asks the login again.

## [5.3.0] — 2026-10-24

### Added

- The profile of the session in the tokens: `locale`, `zoneinfo` and `picture` (OpenID Connect Core § 5.1), copied
  from the host's session when it carries them, checked by nothing here. `Stellaegis.Identity` 6.1.0 writes them. A
  refresh keeps those of the login.
- `/connect/userinfo`, `IssuerEndpoints.UserInfoPath`: the claims of the access token presented — `sub`, `email`
  under the scope `email`, `name` and the profile under `profile`.

### Changed

- `name` goes to the access token too, as the profile does: the user information answers from that token, and an
  API that renders a name for nobody in front of it reads it alone. The token grows by these few claims.

## [5.2.0] — 2026-10-23

### Added

- `amr` in the access and the identity tokens: how the person proved who they are, with the values of RFC 8176,
  copied from the `amr` claims of the host's session — as named, or as ASP.NET Core maps them inbound. Written as a
  JSON array even for one method, as OpenID Connect Core requires; a refresh keeps the methods of the login. A
  resource server on `AddStellaegisBearer` reads one `amr` claim per method. `Stellaegis.Identity` 6.0.0 writes
  them; a session that says none gives a token without `amr`, as before.

### Changed

- The example host takes `Stellaegis.Identity` 6.0.0: its `install` creates the first administrator without a
  password and prints the activation link.

## [5.1.0] — 2026-10-23

### Added

- `Stellaegis.Issuer.SqlServer`: the OpenIddict stores on SQL Server, `AddStellaegisIssuerSqlServer` and its options
  under `Stellaegis:Issuer:SqlServer`, the schema `oidc` declared as a module database that
  `Stellaegis.Primitives.Data` 5.2.0 installs and verifies. Its script is the DDL of the model generated on the SQL
  Server provider and frozen, with a binary collation on `client_id`, the name of a scope and the reference of a
  token, which OAuth compares case-sensitively.

### Changed

- The packages run on `Stellaegis.Primitives` 5.2.0.
- With `UseDevelopmentCertificates`, the signing and encryption certificates named in the options are no longer
  checked, being never loaded: a development configuration may keep its placeholders.

### Fixed

- An empty value is absent. `Password` left empty beside an empty `Path` refused the registration — "Password goes
  with Path" —, and a client's `Secret` left empty refused it too, or became the secret of a confidential client:
  an exhaustive `appsettings.json` could not show these keys. A password given without a file is still refused.

## [5.0.0] — 2026-10-21

First release of the packages: the OpenID Connect issuer of the Stellaegis framework — `Stellaegis.Identity.OpenIddict`,
the OIDC routes of `Admin.Identity`, the M2M client of `Stellaegis.Http`, the bearer of `Stellaegis.AspNetCore`,
the `Sessions` page of `Platform.Identity` — extracted apart from the accounts and rewritten on
`Stellaegis.Primitives` 5.1. They start at the major version of the family. The issuer executes: it turns a person
the host authenticated into tokens, and holds the credentials; it knows no account, and what a client means is the
registry's to say.

### What it keeps from the framework

The three flows of OpenIddict — authorization code with PKCE required, client credentials, refresh — and their
lifetimes, the claims `sub`, `email`, `name` and their destinations, the compact token, JWE by default and JWS as an
option, the validation of the person at the authorization and at the refresh, the revocation on a blocked account,
the client credentials obtained and kept at 80 % of their lifetime, the bearer with `MapInboundClaims = false` and
the scopes split, the sessions page.

### What changes for a host coming from the framework

1. **An issuer apart from the accounts.** `Stellaegis.Identity` identifies a person and issues no token; this
   package takes the person the host authenticated — the cookie of Identity, Negotiate — through
   `Stellaegis:Issuer:AuthenticationScheme` or the host's default scheme, and never reads `IAuthUserStore`. The
   account is validated at the authorization and at the refresh by `IActorAdmissions` of
   `Stellaegis.Primitives.AspNetCore` 5.1.0, which the accounts answer for the blocked ones; the issuer answers it
   for the revoked tokens.
2. **The schema `oidc`, installed by a script.** The four OpenIddict tables leave `ident` for a schema of their
   own, declared as a module database, `IssuerDatabase.Value`, installed by `DatabaseLifecycle.InstallAsync` under
   an administration role and verified at every startup under the application's role. The script is the DDL of
   the EF Core model, frozen; EF Core creates nothing at run time — `OpenIddictSeeder` and its `CreateTablesAsync`
   are gone.
3. **No catalog in the code.** `SystemClientRegistry`, its eleven system clients, `StarterKitOidcSeeder` and
   `is_system` are gone: what exists is what the installation declared, through `IssuerCatalog` and
   `IOidcClientProvisioner`, and what the environment adds in `Stellaegis:Issuer:Clients`. A client declared by the
   installation is a client like any other.
4. **A client is public, native or confidential.** A native client — a desktop or mobile application — comes back
   on a loopback address whose port the issuer ignores (RFC 8252 § 7.3); the framework matched every redirect URI
   exactly.
5. **Minimal API.** `/connect/authorize` and `/connect/logout` are mapped by `MapStellaegisIssuer()`; the host
   needs no `AddControllers()` nor `MapControllers()` for them.
6. **The administration routes carry their operations.** `MapIssuerAdminEndpoints()` maps the clients, the
   scopes, the credentials of a module, the revocation and the revoked tokens under `issuer`, each route labelled
   with an operation of `IssuerOperations` — `clients.read`, `clients.write`, `clients.delete`, `scopes.read`,
   `scopes.write`, `scopes.delete`, `tokens.revoke` — that the host translates into its policies; the policies
   `admin:oidc_clients.*`, `admin:oidc_scopes.*` and `identity:blocked-users.read`, and `AdminApi`, are gone. A
   secret is returned once, at creation or rotation, and never read back.
7. **One section, `Stellaegis:Issuer`**, one sub-section per concern — `PostgreSQL`, `Certificates`, `Clients`,
   `Bearer`, `Admission`, `M2M`, `Client`, `Pages` —, bound by the registrations and validated at startup.
   `Stellaegis:Identity:OpenIddict:*` and `Stellaegis:ThisService:M2M` are gone.
8. **The certificates of production are options**, a PKCS #12 file or a thumbprint, validated at startup: outside
   `Development` the development certificates are refused and the signing certificate is required.
9. **`Stellaegis.Issuer.Client` for every host that is not the issuer**: `AddStellaegisBearer` replaces
   `AddStellaegisAuthentication`, `AddStellaegisIssuerAdmission` with `RevokedTokens` replaces the revoked-tokens
   half of `IUserSecurityCache` and `SecurityCacheReconciliationService`, `AddStellaegisIssuerClient` replaces
   `HttpRevokedTokensSource`, `AddStellaegisIssuerM2M` with `M2MTokenProvider` and `M2MTokenHandler` replaces
   `Stellaegis.Http`. The issuer itself takes this package: it is a resource server for its own routes.
10. **The revocation is announced**, `TokenRevokedEvent` on the `IEventPublisher` of Primitives, and applied by
    the host from its bus; `TokenRevokedEvent` and `UserBlockedEvent` of `Backplane.Core` are gone. The module
    subscribes to nothing: the host calls `ITokenRevoker.RevokeSubjectAsync` from its subscription to the
    `UserBlocked` event of the accounts.
11. **The sessions page is a Razor class library**, `Stellaegis.Issuer.Server`, rendered among the account pages
    of `Stellaegis.Identity.Server` or alone, with its texts in English and in French; it lists an authorization
    only while an application still holds an access or a refresh token of it.
12. **OpenIddict 7.6.0 → 7.7.2**, the Npgsql provider of EF Core 10.0.3.
