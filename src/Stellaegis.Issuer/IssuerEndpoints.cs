using System.Collections.Immutable;
using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;
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

    private static async Task<IResult> AuthorizeAsync(
        HttpContext http, IOpenIddictScopeManager scopes, IOpenIddictApplicationManager applications, IActorAdmissions admissions,
        IDataProtectionProvider protection, IOptions<IssuerOptions> options, TimeProvider clock, CancellationToken ct)
    {
        var request = http.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenID Connect request was not read: the authorization route is served without the OpenIddict server.");
        var scheme = options.Value.AuthenticationScheme;
        var prompted = protection.CreateProtector(PromptedPurpose).ToTimeLimitedDataProtector();

        // The host's authentication may not be the default scheme: read the person from the one named.
        var user = http.User;
        if (scheme is not null)
        {
            var authenticated = await http.AuthenticateAsync(scheme);
            user = authenticated.Succeeded ? authenticated.Principal : new ClaimsPrincipal(new ClaimsIdentity());
        }

        // prompt=none: the application shows no page — an answer, or login_required, never the login.
        var silent = request.HasPromptValue(PromptValues.None);
        if (user.Identity?.IsAuthenticated != true)
            return silent ? Forbid(Errors.LoginRequired, "No session is open, and prompt=none asks for no login.") : Challenge(http, scheme, request, prompted, clock);

        // Back from the login this authorization sent the person to: what it asked of the login is answered. Otherwise
        // the request's prompt, or the client's own when the request says none.
        var answered = WasPrompted(http, request, prompted);
        var prompt = answered ? ClientPrompt.Silent
            : request.HasPromptValue(PromptValues.Login) ? ClientPrompt.Login
            : request.HasPromptValue(PromptValues.SelectAccount) ? ClientPrompt.SelectAccount
            : string.IsNullOrEmpty(request.Prompt) && await applications.FindByClientIdAsync(request.ClientId!, ct) is { } application
                ? IssuerCatalog.PromptOf(await applications.GetPropertiesAsync(application, ct))
                : ClientPrompt.Silent;

        // A login asked again — prompt=login, or a max_age the login of the session is older than, or does not say the
        // time of: the session is closed and the person sent to sign in.
        var authenticatedAt = AuthenticationTime(user);
        if (prompt == ClientPrompt.Login
            || !answered && request.MaxAge is { } maxAge && (authenticatedAt is not { } at || clock.GetUtcNow() - at > TimeSpan.FromSeconds(maxAge)))
        {
            if (silent)
                return Forbid(Errors.LoginRequired, "A new login is asked, and prompt=none asks for no login.");
            await TrySignOutAsync(http, scheme);
            return Challenge(http, scheme, request, prompted, clock);
        }

        // prompt=select_account: the session stays open, and the login page shows it — to continue it, or to switch.
        if (prompt == ClientPrompt.SelectAccount)
            return Challenge(http, scheme, request, prompted, clock);

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
        // When, as the session says it: a refresh keeps the time of the login, as it keeps its methods.
        if (authenticatedAt is { } time)
            identity.AddClaim(new Claim(Claims.AuthenticationTime, time.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64));

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

    /// <summary>
    /// The parameter the way back from the login carries, saying that this authorization sent the person to sign in:
    /// what it asked of the login — the request's <c>prompt</c> or <c>max_age</c>, the client's own <see cref="ClientPrompt"/>
    /// — is then answered. Without it the client's posture, which no request carries, would send the person round.
    /// </summary>
    internal const string PromptedParameter = "stellaegis_prompted";

    private const string PromptedPurpose = "Stellaegis.Issuer.Authorization.Prompted";

    // Long enough for a login with its second factor; a way back older than this asks the login again.
    private static readonly TimeSpan PromptedLifetime = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Sends the person to sign in on the host's scheme, coming back to this authorization without what it asked of
    /// the login — <c>prompt</c>, <c>max_age</c> — and with <see cref="PromptedParameter"/>: the login just done
    /// answers it, and asking it again would send the person round, the more so on a scheme that says no <c>auth_time</c>.
    /// The mark is protected and bound to this request, so that nobody writes it to skip a login.
    /// </summary>
    private static IResult Challenge(HttpContext http, string? scheme, OpenIddictRequest request, ITimeLimitedDataProtector prompted, TimeProvider clock)
    {
        var query = QueryHelpers.ParseQuery(http.Request.QueryString.Value)
            .Where(parameter => parameter.Key is not (Parameters.Prompt or Parameters.MaxAge or PromptedParameter))
            .SelectMany(parameter => parameter.Value.Select(value => KeyValuePair.Create(parameter.Key, value)))
            .Append(KeyValuePair.Create(PromptedParameter, (string?)prompted.Protect(Fingerprint(request), clock.GetUtcNow() + PromptedLifetime)));
        var properties = new AuthenticationProperties { RedirectUri = http.Request.PathBase + http.Request.Path + QueryString.Create(query) };
        return scheme is null ? Results.Challenge(properties) : Results.Challenge(properties, [scheme]);
    }

    /// <summary>Whether this request is the way back of a login this authorization sent the person to, its mark unspent and its own.</summary>
    private static bool WasPrompted(HttpContext http, OpenIddictRequest request, ITimeLimitedDataProtector prompted)
    {
        if (http.Request.Query[PromptedParameter].ToString() is not { Length: > 0 } mark)
            return false;
        try
        {
            return prompted.Unprotect(mark) == Fingerprint(request);
        }
        catch (CryptographicException)
        {
            return false;   // forged, expired, or protected by another key ring: the login is asked
        }
    }

    // What binds the mark to its authorization: the client, where it comes back, its PKCE challenge and its state.
    private static string Fingerprint(OpenIddictRequest request)
        => string.Join('\n', request.ClientId, request.RedirectUri, request.CodeChallenge, request.State);

    /// <summary>When the person of the session authenticated, its <c>auth_time</c> in seconds since the epoch; <see langword="null"/> when the session does not say.</summary>
    private static DateTimeOffset? AuthenticationTime(ClaimsPrincipal user)
        => long.TryParse(user.FindFirst(Claims.AuthenticationTime)?.Value, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds)
            && seconds <= DateTimeOffset.MaxValue.ToUnixTimeSeconds()
            ? DateTimeOffset.FromUnixTimeSeconds(seconds)
            : null;

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
        Claims.Subject or Claims.Email or Claims.AuthenticationMethodReference or Claims.AuthenticationTime or Claims.Name
            or Claims.Locale or Claims.Zoneinfo or Claims.Picture
            => [OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken],
        _ => [],
    };
}
