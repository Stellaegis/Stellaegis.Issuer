using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Stellaegis.Issuer.Server.Pages;

/// <summary>
/// The sessions the issuer opened for the signed-in person — one per application that signed in on their behalf
/// —, each one to end, or all at once, which also signs the person out of the host.
/// </summary>
[Authorize]
internal sealed class SessionsModel(
    IOpenIddictAuthorizationManager authorizations,
    IOpenIddictApplicationManager applications,
    IOpenIddictTokenManager tokens,
    ITokenRevoker revoker,
    IOptions<IssuerPagesOptions> options,
    TimeProvider clock) : PageModel
{
    /// <summary>The sessions of the person, the most recent first.</summary>
    public IReadOnlyList<Session> Sessions { get; private set; } = [];

    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        if (Subject() is not { } subject)
            return Forbid();
        Sessions = await LoadAsync(subject, cancellationToken);
        return Page();
    }

    public async Task<IActionResult> OnPostRevokeAsync(string? authorizationId, CancellationToken cancellationToken)
    {
        if (Subject() is not { } subject)
            return Forbid();
        var authorization = string.IsNullOrWhiteSpace(authorizationId) ? null : await authorizations.FindByIdAsync(authorizationId, cancellationToken);
        if (authorization is null || await authorizations.GetSubjectAsync(authorization, cancellationToken) != subject)
        {
            TempData["Error"] = "Sessions.NotYours";
            return RedirectToPage();
        }
        await revoker.RevokeAuthorizationAsync(authorizationId!, cancellationToken);
        TempData["Notice"] = "Sessions.Revoked";
        return RedirectToPage();
    }

    public async Task<IActionResult> OnPostRevokeAllAsync(CancellationToken cancellationToken)
    {
        if (Subject() is not { } subject)
            return Forbid();
        await revoker.RevokeSubjectAsync(subject, cancellationToken);
        await TrySignOutAsync();
        return LocalRedirect(options.Value.AfterRevokeAllPath);
    }

    private string? Subject()
        => User.Identity?.IsAuthenticated == true
            ? User.FindFirstValue(Claims.Subject) ?? User.FindFirstValue(ClaimTypes.NameIdentifier)
            : null;

    private async Task<IReadOnlyList<Session>> LoadAsync(string subject, CancellationToken cancellationToken)
    {
        var sessions = new List<Session>();
        var now = clock.GetUtcNow();
        await foreach (var authorization in authorizations.FindBySubjectAsync(subject, cancellationToken))
        {
            if (await authorizations.GetStatusAsync(authorization, cancellationToken) != Statuses.Valid)
                continue;
            var id = await authorizations.GetIdAsync(authorization, cancellationToken);
            if (id is null)
                continue;

            // A session is what an application holds: its access and refresh tokens still valid. An authorization
            // whose code was never exchanged, or whose every token expired, is no session to show — nothing is
            // signed in on the person's behalf.
            var active = 0;
            DateTimeOffset? until = null;
            await foreach (var token in tokens.FindByAuthorizationIdAsync(id, cancellationToken))
            {
                if (await tokens.GetStatusAsync(token, cancellationToken) != Statuses.Valid)
                    continue;
                var expires = await tokens.GetExpirationDateAsync(token, cancellationToken);
                if (expires is not null && expires <= now)
                    continue;
                var type = await tokens.GetTypeAsync(token, cancellationToken);
                if (type != TokenTypeIdentifiers.AccessToken && type != TokenTypeIdentifiers.RefreshToken)
                    continue;
                active++;
                if (type == TokenTypeIdentifiers.RefreshToken && (until is null || expires > until))
                    until = expires;
            }
            if (active == 0)
                continue;

            var applicationId = await authorizations.GetApplicationIdAsync(authorization, cancellationToken);
            var application = applicationId is null ? null : await applications.FindByIdAsync(applicationId, cancellationToken);
            var clientName = application is null
                ? "?"
                : await applications.GetDisplayNameAsync(application, cancellationToken) ?? await applications.GetClientIdAsync(application, cancellationToken) ?? "?";
            sessions.Add(new Session(id, clientName, await authorizations.GetCreationDateAsync(authorization, cancellationToken) ?? now, until, active));
        }
        return sessions.OrderByDescending(session => session.CreatedAt).ToList();
    }

    /// <summary>Signs out of the host's scheme when it can sign out — a cookie can, Negotiate cannot, and that is no error.</summary>
    private async Task TrySignOutAsync()
    {
        try
        {
            await HttpContext.SignOutAsync();
        }
        catch (InvalidOperationException)
        {
            // No sign-out handler: nothing to end on the host.
        }
    }

    /// <summary>A session as the page shows it.</summary>
    /// <param name="AuthorizationId">The authorization the issuer opened, what the person ends.</param>
    /// <param name="ClientName">The application signed in.</param>
    /// <param name="CreatedAt">When the person signed in to it.</param>
    /// <param name="ExpiresAt">When its refresh token expires, when it has one still valid.</param>
    /// <param name="ActiveTokens">How many of its tokens are still valid.</param>
    public sealed record Session(string AuthorizationId, string ClientName, DateTimeOffset CreatedAt, DateTimeOffset? ExpiresAt, int ActiveTokens);
}
