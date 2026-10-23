-- ============================================================================
-- Stellaegis.Issuer — the issuer schema on SQL Server, script 0001
-- ============================================================================
-- Applied by the installation of the application (DatabaseLifecycle.InstallAsync of
-- Stellaegis.Primitives.Data), under a login that owns the schema; the schema is created by the
-- installation before this script. The application connects as a member of the database role the
-- installation grants its data rights. The record of the scripts applied is the installation's,
-- oidc._schema_migrations, not this script's.
--
-- These four tables are the OpenIddict stores, as its EF Core model shapes them
-- (OpenIddict.EntityFrameworkCore 7.7, snake-case names, schema oidc — IssuerDbContext of
-- Stellaegis.Issuer). This DDL was generated once from that model on the SQL Server provider,
-- then read and frozen here: EF Core reads and writes these tables at run time and never
-- creates nor migrates them. A change of the OpenIddict model is a new numbered script.
--
-- Three departures from the generated DDL, or from the conventions of a schema of ours, and why:
--   * client_id, the name of a scope and the reference of a token carry a binary collation. The
--     identifiers of OAuth are case-sensitive (RFC 6749), and a database of SQL Server is usually
--     case-insensitive: without it, Desktop and desktop would be one client, and two references
--     differing only by case one token. It keeps what PostgreSQL compares;
--   * the instants are datetime2, not datetimeoffset: the model holds them as DateTime in UTC, and
--     EF Core reads no other type into it;
--   * the unique indexes are filtered on the values present: a unique index of SQL Server counts
--     its nulls as equal, and most tokens have no reference. EF Core generates them so.
-- The two composite indexes can exceed, on paper, the 1700 bytes of a nonclustered key, which SQL
-- Server creates with a warning; the values held — identifiers, constants — stay far below it.
--
-- No row-level security: the module has no compartment, every row belongs to the application.
-- No table of an account: the accounts are Stellaegis.Identity's, in a schema of their own.
-- All constraints explicitly named.
-- ============================================================================

-- ── Applications — the clients ───────────────────────────────────────────────
-- A client, public (authorization code with PKCE) or confidential (client credentials); its secret
-- is hashed by OpenIddict and never read back. The columns ending in -s hold JSON written by the
-- OpenIddict stores; concurrency_token is the optimistic concurrency stamp of EF Core.

create table oidc.applications (
  id                        nvarchar(450) not null,
  application_type          nvarchar(50)  null,
  client_id                 nvarchar(100) collate Latin1_General_100_BIN2 null,
  client_secret             nvarchar(max) null,
  client_type               nvarchar(50)  null,
  concurrency_token         nvarchar(50)  null,
  consent_type              nvarchar(50)  null,
  display_name              nvarchar(max) null,
  display_names             nvarchar(max) null,
  json_web_key_set          nvarchar(max) null,
  permissions               nvarchar(max) null,
  post_logout_redirect_uris nvarchar(max) null,
  properties                nvarchar(max) null,
  redirect_uris             nvarchar(max) null,
  requirements              nvarchar(max) null,
  settings                  nvarchar(max) null,

  constraint pk_applications primary key (id)
);

create unique index ix_applications_client_id on oidc.applications (client_id) where client_id is not null;

-- ── Scopes ───────────────────────────────────────────────────────────────────
-- A scope is the name of a module, and its resources carry the same name as audience.

create table oidc.scopes (
  id                nvarchar(450) not null,
  concurrency_token nvarchar(50)  null,
  description       nvarchar(max) null,
  descriptions      nvarchar(max) null,
  display_name      nvarchar(max) null,
  display_names     nvarchar(max) null,
  name              nvarchar(200) collate Latin1_General_100_BIN2 null,
  properties        nvarchar(max) null,
  resources         nvarchar(max) null,

  constraint pk_scopes primary key (id)
);

create unique index ix_scopes_name on oidc.scopes (name) where name is not null;

-- ── Authorizations — the sessions of a subject with a client ─────────────────
-- Revoking one ends the session and its tokens; the subject is the sub of the tokens.

create table oidc.authorizations (
  id                nvarchar(450) not null,
  application_id    nvarchar(450) null,
  concurrency_token nvarchar(50)  null,
  creation_date     datetime2     null,
  properties        nvarchar(max) null,
  scopes            nvarchar(max) null,
  status            nvarchar(50)  null,
  subject           nvarchar(400) null,
  type              nvarchar(50)  null,

  constraint pk_authorizations primary key (id),
  constraint fk_authorizations_applications_application_id
    foreign key (application_id) references oidc.applications (id)
);

create index ix_authorizations_application_id_status_subject_type
  on oidc.authorizations (application_id, status, subject, type);

-- ── Tokens ───────────────────────────────────────────────────────────────────
-- Every token issued, access, identity, refresh and authorization code, with its status: a revoked
-- access token not yet expired is what IRevokedTokensSource lists for the resource servers. The
-- payload is set for reference tokens only; the id is the oi_tkn_id claim of a signed token.

create table oidc.tokens (
  id                nvarchar(450) not null,
  application_id    nvarchar(450) null,
  authorization_id  nvarchar(450) null,
  concurrency_token nvarchar(50)  null,
  creation_date     datetime2     null,
  expiration_date   datetime2     null,
  payload           nvarchar(max) null,
  properties        nvarchar(max) null,
  redemption_date   datetime2     null,
  reference_id      nvarchar(100) collate Latin1_General_100_BIN2 null,
  status            nvarchar(50)  null,
  subject           nvarchar(400) null,
  type              nvarchar(150) null,

  constraint pk_tokens primary key (id),
  constraint fk_tokens_applications_application_id
    foreign key (application_id) references oidc.applications (id),
  constraint fk_tokens_authorizations_authorization_id
    foreign key (authorization_id) references oidc.authorizations (id)
);

create index ix_tokens_application_id_status_subject_type
  on oidc.tokens (application_id, status, subject, type);
create index ix_tokens_authorization_id on oidc.tokens (authorization_id);
create unique index ix_tokens_reference_id on oidc.tokens (reference_id) where reference_id is not null;
