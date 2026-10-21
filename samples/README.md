# The example, in two processes

What an application assembled on `Stellaegis.Issuer` looks like when a service lives apart from the host that
issues the tokens. Two hosts, one PostgreSQL server, no package of the framework beyond the family's.

| Host | Port | What it is |
| --- | --- | --- |
| `Stellaegis.Issuer.Sample.Identity` | 7111 | The accounts (`Stellaegis.Identity`, from NuGet) and the issuer, in one process: the pages a person signs in with, the sessions page, the protocol routes under `/connect`, the administration routes of both under `/api/admin`. It is also a resource server for its own administration routes. |
| `Stellaegis.Issuer.Sample.Inventory` | 7112 | A resource server with one module, `inventory`, on `Stellaegis.Issuer.Client` alone: it accepts the issuer's tokens, refuses the revoked ones, and calls the issuer with its own credentials. |

Both run in the `Development` environment: the issuer signs with development certificates, which it refuses
anywhere else, and the HTTPS development certificate of the machine must be trusted
(`dotnet dev-certs https --trust`).

## Installing

A PostgreSQL server reachable at `127.0.0.1` as `postgres` without a password — change `Sample:Install:ConnectionString`
otherwise. The installation is a verb of the first host, apart from serving:

```powershell
cd samples/Stellaegis.Issuer.Sample.Identity
dotnet run -- install --admin-email admin@acme.test --admin-password 'Correct-Horse-9'
```

It creates the database `stellaegis_issuer_sample` and the role `issuer_sample_app` if missing, installs the
schemas `ident` and `oidc` under the administration connection — one database, two schemas, one role: the example
shares the instance, a deployment splits them by configuration alone —, creates the administrator, provisions the
credentials of the `inventory` module (its scope, its confidential client), creates the scope `issuer` and grants
it to the inventory, declares the public client `desktop`, and re-applies what the configuration says of the
clients: the secret of the inventory, the redirect URIs of the desktop (`Stellaegis:Issuer:Clients`). Run again, it
changes nothing.

⚠ Re-applying the secret of the inventory from the issuer's configuration is a shortcut for reproducibility, not the
rule: the issuer keeps only the hash of a secret and has no business holding it in clear. In a deployment, `install`
provisions the module and prints the secret once; it goes to the vault or the configuration of the one service that
uses it, and a rotation goes through the issuer's `apis/{module}/rotate` route, which returns the new secret once.

## Running

Two terminals:

```powershell
cd samples/Stellaegis.Issuer.Sample.Identity; dotnet run
cd samples/Stellaegis.Issuer.Sample.Inventory; dotnet run
```

The first verifies the two schemas under the application's role before serving — a schema missing stops it —
and serves `https://localhost:7111`: `/login`, `/account`, `/account/sessions`, `/.well-known/openid-configuration`.
The second serves `https://localhost:7112`: `GET /api/items` and `GET /api/issuer/scopes`, both under a bearer
token carrying the scope `inventory`. At startup it reads the revoked tokens from the issuer with its own
credentials, and then every five seconds.

## The native flow, by hand

What the desktop application does (RFC 8252): the system browser opens the authorization route, the person signs
in on the pages, the browser comes back to a loopback address with a code, and the application exchanges the code
with the PKCE verifier. Here with PowerShell and `curl`:

```powershell
# 1. A PKCE verifier and its challenge.
$bytes = [byte[]]::new(32); [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
$verifier  = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
$hash      = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::ASCII.GetBytes($verifier))
$challenge = [Convert]::ToBase64String($hash).TrimEnd('=').Replace('+','-').Replace('/','_')

# 2. The authorization, in the browser: sign in, then read the code in the address the browser lands on —
#    nothing listens on the loopback here, the page fails to load and the URL holds the code.
Start-Process "https://localhost:7111/connect/authorize?client_id=desktop&redirect_uri=http://127.0.0.1:7890/callback&response_type=code&scope=openid%20offline_access%20email%20profile%20inventory&code_challenge=$challenge&code_challenge_method=S256&state=xyz"
$code = Read-Host "code"

# 3. The exchange, then the call.
$tokens = curl.exe -s https://localhost:7111/connect/token -d grant_type=authorization_code -d client_id=desktop -d code=$code -d code_verifier=$verifier -d redirect_uri=http://127.0.0.1:7890/callback | ConvertFrom-Json
curl.exe -s https://localhost:7112/api/items -H "Authorization: Bearer $($tokens.access_token)"
curl.exe -s https://localhost:7112/api/issuer/scopes -H "Authorization: Bearer $($tokens.access_token)"

# 4. A refresh.
curl.exe -s https://localhost:7111/connect/token -d grant_type=refresh_token -d client_id=desktop -d refresh_token=$($tokens.refresh_token)
```

The client `desktop` is declared *native*, and its redirect URI as `http://127.0.0.1/callback`: a loopback
address, whose port the issuer ignores for a native client, so that the application listens on whatever port is
free (RFC 8252). Ending the session on `/account/sessions` revokes the
tokens; the inventory refuses them at its next reading, within five seconds, with `Token.Revoked`.

## The credentials of a service

The inventory speaks as itself with the client credentials the installation provisioned, `Stellaegis:Issuer:M2M`:
`GET /api/issuer/scopes` calls the issuer's `GET /api/admin/issuer/scopes` with the token obtained for the scope
`issuer`, attached by `AddM2MToken("issuer")`. The same credentials present the host to the issuer's
`security/revoked-tokens`, which the admission reads.

```powershell
curl.exe -s https://localhost:7111/connect/token -d grant_type=client_credentials -d client_id=inventory -d client_secret=inventory-sample-secret-change-me-per-deployment -d scope=inventory
```
