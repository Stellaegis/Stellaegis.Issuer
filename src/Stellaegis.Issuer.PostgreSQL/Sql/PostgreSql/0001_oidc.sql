-- ============================================================================
-- Stellaegis.Issuer — the issuer schema, script 0001
-- ============================================================================
-- Applied by the installation of the application (DatabaseLifecycle.InstallAsync of
-- Stellaegis.Primitives.Data), under the role that owns the schema; the schema is created by the
-- installation before this script. The application connects under an ordinary role, granted its
-- data rights by the installation. The record of the scripts applied is the installation's,
-- oidc._schema_migrations, not this script's.
--
-- These four tables are the OpenIddict stores, as its EF Core model shapes them
-- (OpenIddict.EntityFrameworkCore 7.7, snake-case names, schema oidc — IssuerDbContext of
-- Stellaegis.Issuer). This DDL was generated once from that model on the Npgsql provider,
-- then read and frozen here: EF Core reads and writes these tables at run time and never
-- creates nor migrates them. A change of the OpenIddict model is a new numbered script.
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
  id                        text                   not null,
  application_type          character varying(50),
  client_id                 character varying(100),
  client_secret             text,
  client_type               character varying(50),
  concurrency_token         character varying(50),
  consent_type              character varying(50),
  display_name              text,
  display_names             text,
  json_web_key_set          text,
  permissions               text,
  post_logout_redirect_uris text,
  properties                text,
  redirect_uris             text,
  requirements              text,
  settings                  text,

  constraint pk_applications primary key (id)
);

create unique index ix_applications_client_id on oidc.applications (client_id);

-- ── Scopes ───────────────────────────────────────────────────────────────────
-- A scope is the name of a module, and its resources carry the same name as audience.

create table oidc.scopes (
  id                text                   not null,
  concurrency_token character varying(50),
  description       text,
  descriptions      text,
  display_name      text,
  display_names     text,
  name              character varying(200),
  properties        text,
  resources         text,

  constraint pk_scopes primary key (id)
);

create unique index ix_scopes_name on oidc.scopes (name);

-- ── Authorizations — the sessions of a subject with a client ─────────────────
-- Revoking one ends the session and its tokens; the subject is the sub of the tokens.

create table oidc.authorizations (
  id                text                     not null,
  application_id    text,
  concurrency_token character varying(50),
  creation_date     timestamp with time zone,
  properties        text,
  scopes            text,
  status            character varying(50),
  subject           character varying(400),
  type              character varying(50),

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
  id                text                     not null,
  application_id    text,
  authorization_id  text,
  concurrency_token character varying(50),
  creation_date     timestamp with time zone,
  expiration_date   timestamp with time zone,
  payload           text,
  properties        text,
  redemption_date   timestamp with time zone,
  reference_id      character varying(100),
  status            character varying(50),
  subject           character varying(400),
  type              character varying(150),

  constraint pk_tokens primary key (id),
  constraint fk_tokens_applications_application_id
    foreign key (application_id) references oidc.applications (id),
  constraint fk_tokens_authorizations_authorization_id
    foreign key (authorization_id) references oidc.authorizations (id)
);

create index ix_tokens_application_id_status_subject_type
  on oidc.tokens (application_id, status, subject, type);
create index ix_tokens_authorization_id on oidc.tokens (authorization_id);
create unique index ix_tokens_reference_id on oidc.tokens (reference_id);
