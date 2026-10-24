using System.Collections.Immutable;
using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using Stellaegis.Primitives;
using Stellaegis.Primitives.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Stellaegis.Issuer;

/// <summary>
/// Maps the protocol routes of the issuer. The token route, <c>/connect/token</c>, is OpenIddict's own, served by
/// the authentication pipeline; the three others are the issuer's: the authorization, which turns a person the host
/// has authenticated into a code, the user information, and the logout.
/// </summary>
/// <remarks>
/// <para>
/// At <c>/connect/authorize</c>, a person nobody has authenticated is challenged on the host's scheme —
/// <see cref="IssuerOptions.AuthenticationScheme"/>, or the host's default: the cookie of Stellaegis.Identity,
/// Negotiate —, and comes back once signed in. An authenticated person is first asked of every
/// <c>IActorAdmission</c> registered — a blocked account is refused there, whatever the cookie says —: a refusal
/// signs the person out of the scheme and sends the client <c>access_denied</c> with the reason. Then the principal
/// is signed by OpenIddict with the claims <c>sub</c>, <c>email</c> and <c>name</c>, <c>amr</c>, and the profile the
/// session carries — <c>locale</c>, <c>zoneinfo</c>, <c>picture</c> (OpenID Connect Core § 5.1) —, the scopes
/// requested, and as audiences the resources of those scopes — a scope is the name of a module. A refresh keeps the
/// claims of the login: a language changed reaches the tokens at the next one.
/// </para>
/// <para>
/// At <c>/connect/userinfo</c>, the claims of the access token presented: <c>sub</c>, <c>email</c> under the scope
/// <c>email</c>, <c>name</c> and the profile under <c>profile</c>. The issuer reads no account: what it answers is what
/// the login put in the token.
/// </para>
/// <para>The routes are anonymous by nature and carry no operation: the client speaks with its own credentials.</para>
/// <para>
/// ⚠ A host that enables <c>UseStellaegisActorAdmission()</c> of Primitives on its whole pipeline refuses a blocked
/// person at the door, with 401 and problem details, before the authorization route can send the client
/// <c>access_denied</c> and sign the person out. On a host that serves the issuer beside resource routes, enable the
/// door on the resource routes — <c>app.UseWhen(context => !context.Request.Path.StartsWithSegments("/connect"), door => door.UseStellaegisActorAdmission())</c>
/// —, or accept the 401: either way nothing is issued to a refused person, and the token route asks the admissions
/// itself at every refresh.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// builder.Services.AddStellaegisIssuerPostgreSQL(builder.Configuration);
/// var app = builder.Build();
/// app.UseAuthentication();
/// app.UseStellaegisActorAdmission();
/// app.UseAuthorization();
/// app.MapStellaegisIssuer();
/// </code>
/// </example>
public static class IssuerEndpoints
{
    /// <summary>The authorization route, <c>/connect/authorize</c>.</summary>
    public const string AuthorizePath = "/connect/authorize";

    /// <summary>The token route, <c>/connect/token</c>, served by OpenIddict.</summary>
    public const string TokenPath = "/connect/token";

    /// <summary>The logout route, <c>/connect/logout</c>.</summary>
    public const string LogoutPath = "/connect/logout";

    /// <summary>The user information route, <c>/connect/userinfo</c>.</summary>
    public const string UserInfoPath = "/connect/userinfo";

    // The profile a session may carry (OpenID Connect Core § 5.1), copied as is: the issuer checks none of it.
    private static readonly string[] ProfileClaims = [Claims.Locale, Claims.Zoneinfo, Claims.Picture];

    private static readonly string[] SubjectClaims = [Claims.Subject, ClaimTypes.NameIdentifier];

    // amr as the host's scheme names it: as is, or under the name ASP.NET Core maps it to when it maps inbound claims.
    private static readonly string[] MethodClaims = [Claims.AuthenticationMethodReference, "http://schemas.microsoft.com/claims/authnmethodsreferences"];

    /// <summary>
    /// Maps the authorization, the user information and the logout routes. Call it after <c>UseAuthentication()</c>, so that the host's
    /// scheme has read the person, and after <c>UseStellaegisActorAdmission()</c> when the host enables it.
    /// </summary>
    public static IEndpointRouteBuilder MapStellaegisIssuer(this IEndpointRouteBuilder endpoints)
    {
        Guard.NotNull(endpoints);
        endpoints.MapGet(AuthorizePath, AuthorizeAsync).AllowAnonymous();
        // Cast: a handler taking the HttpContext alone would be read as a RequestDelegate, its result discarded.
        endpoints.MapMethods(UserInfoPath, [HttpMethods.Get, HttpMethods.Post], (Func<HttpContext, Task<IResult>>)UserInfoAsync).AllowAnonymous();
        endpoints.MapMethods(LogoutPath, [HttpMethods.Get, HttpMethods.Post], LogoutAsync).AllowAnonymous();
        return endpoints;
    }

    private static async Task<IResult> AuthorizeAsync(HttpContext http, IOpenIddictScopeManager scopes, IActorAdmissions admissions, IOptions<IssuerOptions> options, CancellationToken ct)
    {
        var request = http.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenID Connect request was not read: the authorization route is served without the OpenIddict server.");
        var scheme = options.Value.AuthenticationScheme;

        // The host's authentication may not be the default scheme: read the person from the one named.
        var user = http.User;
        if (scheme is not null)
        {
            var authenticated = await http.AuthenticateAsync(scheme);
            user = authenticated.Succeeded ? authenticated.Principal : new ClaimsPrincipal(new ClaimsIdentity());
        }

        if (user.Identity?.IsAuthenticated != true)
            return Challenge(http, scheme);

        var admitted = await admissions.AdmitAsync(user, ct);
        if (admitted.IsFailure)
        {
            await TrySignOutAsync(http, scheme);
            return Forbid(Errors.AccessDenied, admitted.Error!.Message);
        }

        var subject = SubjectClaims.Select(type => user.FindFirst(type)?.Value).FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));
        if (subject is null)
            return Result.Failure(IssuerErrors.SubjectMissing).ToHttpResult();

        var identity = new ClaimsIdentity(TokenValidationParametersAuthenticationType, Claims.Name, Claims.Role);
        identity.SetClaim(Claims.Subject, subject);
        if ((user.FindFirst(Claims.Email)?.Value ?? user.FindFirst(ClaimTypes.Email)?.Value) is { } email)
            identity.SetClaim(Claims.Email, email);
        if ((user.FindFirst(Claims.Name)?.Value ?? user.FindFirst(ClaimTypes.Name)?.Value ?? user.Identity.Name) is { } name)
            identity.SetClaim(Claims.Name, name);
        foreach (var type in ProfileClaims)
        {
            if (user.FindFirst(type)?.Value is { Length: > 0 } value)
                identity.SetClaim(type, value);
        }

        // How the person proved who they are, as the session says (RFC 8176): a decision then asks whether a second
        // factor was used for this session, not whether the account has one. A refresh keeps those of the login; the
        // tokens write them as an array, AuthenticationMethodsHandler.
        var methods = MethodClaims.SelectMany(type => user.FindAll(type)).Select(claim => claim.Value)
            .Where(value => !string.IsNullOrWhiteSpace(value)).Distinct(StringComparer.Ordinal).ToImmutableArray();
        if (methods.Length > 0)
            identity.SetClaims(Claims.AuthenticationMethodReference, methods);

        var requested = request.GetScopes();
        identity.SetScopes(requested);
        var resources = await scopes.ListResourcesAsync(requested, ct).ToListAsync(ct);
        if (resources.Count > 0)
            identity.SetResources(resources);
        identity.SetDestinations(Destinations);

        return Results.SignIn(new ClaimsPrincipal(identity), authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private static async Task<IResult> UserInfoAsync(HttpContext http)
    {
        // OpenIddict validated the access token before this handler runs; its principal is the token's.
        var authenticated = await http.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        if (authenticated.Principal is not { } principal || principal.GetClaim(Claims.Subject) is not { } subject)
        {
            return Results.Challenge(new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidToken,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The access token does not name a person.",
            }), [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
        }

        var claims = new Dictionary<string, string>(StringComparer.Ordinal) { [Claims.Subject] = subject };
        if (principal.HasScope(Scopes.Email) && principal.GetClaim(Claims.Email) is { } email)
            claims[Claims.Email] = email;
        if (principal.HasScope(Scopes.Profile))
        {
            foreach (var type in ProfileClaims.Prepend(Claims.Name))
            {
                if (principal.GetClaim(type) is { } value)
                    claims[type] = value;
            }
        }
        return Results.Ok(claims);
    }

    private static async Task<IResult> LogoutAsync(HttpContext http, IOptions<IssuerOptions> options)
    {
        await TrySignOutAsync(http, options.Value.AuthenticationScheme);
        return Results.SignOut(
            new AuthenticationProperties { RedirectUri = "/" },
            [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
    }

    /// <summary>The authentication type of the identities OpenIddict signs, what its own handlers use.</summary>
    private const string TokenValidationParametersAuthenticationType = "AuthenticationTypes.Federation";

    private static IResult Challenge(HttpContext http, string? scheme)
    {
        var properties = new AuthenticationProperties { RedirectUri = http.Request.PathBase + http.Request.Path + http.Request.QueryString };
        return scheme is null ? Results.Challenge(properties) : Results.Challenge(properties, [scheme]);
    }

    private static IResult Forbid(string error, string description)
    {
        var properties = new AuthenticationProperties(new Dictionary<string, string?>
        {
            [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description,
        });
        return Results.Forbid(properties, [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
    }

    /// <summary>Signs out of the host's scheme when it can sign out — a cookie can, a bearer or Negotiate cannot, and that is no error.</summary>
    private static async Task TrySignOutAsync(HttpContext http, string? scheme)
    {
        try
        {
            if (scheme is null)
                await http.SignOutAsync();
            else
                await http.SignOutAsync(scheme);
        }
        catch (InvalidOperationException)
        {
            // The scheme has no sign-out handler, or no default sign-out scheme is configured: nothing to end.
        }
    }

    /// <summary>
    /// Where each claim goes: <c>sub</c>, <c>email</c>, <c>amr</c>, <c>name</c> and the profile to both tokens, nothing
    /// else anywhere — the token stays compact. The access token carries the name and the profile because the user
    /// information answers from it, and because an API that renders a date or a name for nobody in front of it — a
    /// PDF, an e-mail — reads that token alone.
    /// </summary>
    internal static IEnumerable<string> Destinations(Claim claim) => claim.Type switch
    {
        Claims.Subject or Claims.Email or Claims.AuthenticationMethodReference or Claims.Name
            or Claims.Locale or Claims.Zoneinfo or Claims.Picture
            => [OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken],
        _ => [],
    };
}
