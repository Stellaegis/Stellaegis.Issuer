# Stellaegis.Issuer

The OpenID Connect issuer of an application assembled on
[Stellaegis.Primitives](https://github.com/Stellaegis/Stellaegis.Primitives): it takes a user the host has
authenticated — by the cookie of [Stellaegis.Identity](https://github.com/Stellaegis/Stellaegis.Identity), or by any
other scheme — and turns them into tokens; it holds the clients and the scopes, revokes, and gives every resource
server what it needs to accept a bearer token. Built on [OpenIddict](https://github.com/openiddict/openiddict-core).

⚠ Being extracted from the Stellaegis framework. Nothing is published yet; the first version will be 5.0.0.
