# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
