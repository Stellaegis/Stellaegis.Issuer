# Stellaegis.Issuer.Client

What a host that is not the issuer takes of `Stellaegis.Issuer`: the validation of the bearer tokens the issuer
issued, the admission of the revoked tokens, and the client credentials a service speaks with. No OpenIddict here.
The issuer itself takes this package too — its administration routes are called with the tokens it issues, and it
is a resource server for them.

## A resource server

```csharp
builder.Services.AddStellaegisBearer(builder.Configuration);          // Stellaegis:Issuer:Bearer — the authority, the audiences
builder.Services.AddStellaegisIssuerAdmission(builder.Configuration); // Stellaegis:Issuer:Admission — the revoked tokens, read then kept
builder.Services.AddStellaegisIssuerM2M(builder.Configuration);       // Stellaegis:Issuer:M2M — this host's own credentials
builder.Services.AddStellaegisIssuerClient(builder.Configuration);    // Stellaegis:Issuer:Client — where the revoked tokens are read
...
app.UseAuthentication();
app.UseStellaegisActorAdmission();   // of Primitives: every admission registered, the revoked tokens included
app.UseAuthorization();
```

```text
Stellaegis:Issuer:Bearer:Authority = https://id.acme.example
Stellaegis:Issuer:Bearer:Audiences:0 = documents
Stellaegis:Issuer:M2M:Authority = https://id.acme.example
Stellaegis:Issuer:M2M:ClientId = documents
Stellaegis:Issuer:M2M:ClientSecret = …                                 (from a secret store)
Stellaegis:Issuer:Client:BaseUrl = https://id.acme.example/api/admin/issuer
```

**The bearer.** `AddStellaegisBearer` registers the JWT bearer authentication as the default scheme: the issuer as
authority, read through its discovery document; the audiences this host serves, which are the names of its modules;
the claims kept as the token names them — `sub`, `scope` —; the scopes split into one `scope` claim each, for a
policy that requires one. A host that authenticates with several schemes — the cookie of the accounts beside the
bearer — chooses between them with a policy scheme of its own, after this call.

**The admission.** `RevokedTokens` is the `IActorAdmission` of the issuer: an access token revoked before its
expiration is refused at the door with the code `Token.Revoked`, whatever its signature says. It is read from
`IRevokedTokensSource` when the host starts and then every `ReconcileInterval` (two minutes unless set) — the safety
net —, and kept current in between by the host, which calls `RevokedTokens.Revoke(tokenId, expiresAt)` from its
subscription to the `TokenRevoked` event of the issuer on its bus. The source is the issuer's own on the host that
holds it; on a resource server apart, `AddStellaegisIssuerClient` registers the HTTP source, which reads
`GET security/revoked-tokens` of the issuer's administration routes with the token `IIssuerClientTokenProvider`
gives — `AddStellaegisIssuerM2M` registers one over the host's own credentials, for the scope `issuer`, so the
installation grants that scope to every service that reads the issuer.

**The credentials.** `M2MTokenProvider` obtains a token by the `client_credentials` grant for the scope asked — the
name of the module called — and keeps it for 80 % of its lifetime. `M2MTokenHandler` attaches it to every request
of an HTTP client; `AddM2MToken(scope)` puts the handler on a client being built:

```csharp
builder.Services.AddStellaegisHttpClient<IDocumentsClient, HttpDocumentsClient, DocumentsClientOptions>(builder.Configuration, "Stellaegis:Documents:Client")
    .AddM2MToken("documents");
```

A host that reads the blocked accounts of `Stellaegis.Identity` over HTTP gives its client the same credentials, in
one line — this package does not reference Identity, the host connects the two:

```csharp
builder.Services.AddSingleton<IIdentityClientTokenProvider>(provider =>
    new IdentityTokens(provider.GetRequiredService<M2MTokenProvider>()));

sealed class IdentityTokens(M2MTokenProvider tokens) : IIdentityClientTokenProvider
{
    public async ValueTask<string?> GetTokenAsync(CancellationToken ct = default) => await tokens.GetTokenAsync("identity", ct);
}
```

## Encrypted tokens and hosts apart

The issuer encrypts its access tokens unless told otherwise (JWE). An encrypted token is read by nobody but a
resource server holding the encryption certificate's private key, named in `Stellaegis:Issuer:Bearer:Decryption`
(a PKCS #12 file and its password, or a thumbprint). Sharing a private key across hosts is a deployment of its own:
in a distributed topology, the issuer sets `EncryptAccessTokens = false`, and the token — signed, validated by any
resource server with the public keys of the discovery document — stays compact, `sub`, `email`, scopes, audiences,
with nothing in it worth hiding. A single host that holds the issuer and its resource routes keeps the encryption
and decrypts with the same certificate.
