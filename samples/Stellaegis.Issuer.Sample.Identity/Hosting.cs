using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Stellaegis.Identity;
using Stellaegis.Identity.AspNetCore;
using Stellaegis.Issuer.Client;
using Stellaegis.Primitives;

namespace Stellaegis.Issuer.Sample.Identity;

/// <summary>The frame of the example: one compartment, the company whose people the accounts are.</summary>
public static class SampleFrame
{
    public static readonly Compartment Company = Compartment.Parse("acme");

    public static readonly ApplicationFrame Value = ApplicationFrame.SingleCompartment(Company);
}

/// <summary>The policy scheme of the example, which sends a bearer token to the bearer and everything else to the cookie.</summary>
public static class SampleAuthentication
{
    public const string Scheme = "Sample";
}

/// <summary>
/// The mailer of the example: what the pages ask to send goes to the log, where a developer reads the code or
/// the link. A real host implements <see cref="IIdentityMailer"/> on its messaging, with its own wording.
/// </summary>
public sealed class LoggingMailer(ILogger<LoggingMailer> logger) : IIdentityMailer
{
    public Task SendVerificationCodeAsync(string email, string code, TimeSpan lifetime, CancellationToken cancellationToken = default)
    {
        logger.LogWarning("MAIL to {Email}: your verification code is {Code}, valid for {Lifetime}", email, code, lifetime);
        return Task.CompletedTask;
    }

    public Task SendLoginCodeAsync(string email, string code, TimeSpan lifetime, CancellationToken cancellationToken = default)
    {
        logger.LogWarning("MAIL to {Email}: your login code is {Code}, valid for {Lifetime}", email, code, lifetime);
        return Task.CompletedTask;
    }

    public Task SendPasswordResetLinkAsync(string email, Uri link, TimeSpan lifetime, CancellationToken cancellationToken = default)
    {
        logger.LogWarning("MAIL to {Email}: reset your password at {Link}, valid for {Lifetime}", email, link, lifetime);
        return Task.CompletedTask;
    }

    public Task SendActivationLinkAsync(string email, Uri link, TimeSpan lifetime, CancellationToken cancellationToken = default)
    {
        logger.LogWarning("MAIL to {Email}: activate your account at {Link}, valid for {Lifetime}", email, link, lifetime);
        return Task.CompletedTask;
    }

    public Task SendAccountAlreadyExistsAsync(string email, CancellationToken cancellationToken = default)
    {
        logger.LogWarning("MAIL to {Email}: someone tried to register this address, which has an account already", email);
        return Task.CompletedTask;
    }
}

/// <summary>
/// The bus of the example: a single process, so an event is handed to its subscribers straight away. A block
/// applies to the admission without waiting for its next reading, and revokes every token the issuer gave the
/// blocked person — the one subscription the doctrine asks of a host that holds both; an unblock lifts the
/// admission. A revoked token is already refused by this process (the issuer told its own admission) and is
/// logged for the services apart, which read the revoked tokens from the issuer's route. A host with several
/// processes registers the bus of <c>Stellaegis.Backplane</c> instead, and subscribes the same way.
/// </summary>
public sealed class SampleEventPublisher(BlockedAccounts accounts, IServiceScopeFactory scopes, ILogger<SampleEventPublisher> logger) : IEventPublisher
{
    public async Task PublishAsync<TEvent>(TEvent @event, CancellationToken cancellationToken = default) where TEvent : IEvent
    {
        switch (@event)
        {
            case UserBlockedEvent blocked:
                accounts.Block(blocked.UserUniqueId);
                using (var scope = scopes.CreateScope())
                {
                    var revoked = await scope.ServiceProvider.GetRequiredService<ITokenRevoker>()
                        .RevokeSubjectAsync(blocked.UserUniqueId.ToString("N"), cancellationToken);
                    logger.LogInformation("Account {UserUniqueId} blocked: {Count} token(s) revoked", blocked.UserUniqueId, revoked);
                }
                break;
            case UserUnblockedEvent unblocked:
                accounts.Unblock(unblocked.UserUniqueId);
                break;
        }
        logger.LogInformation("Event {Event}", @event);
    }
}

/// <summary>
/// Who may administer, in the example: the people whose e-mail is listed in <c>Sample:Administrators</c>, granted
/// every operation of the accounts and of the issuer; and the services whose token carries the scope
/// <c>issuer</c>, granted the operations of the issuer — the inventory reads the revoked tokens and the scopes
/// that way. A real host answers each policy from its rights system — <c>Stellaegis.Access</c> —, by actor,
/// space and operation.
/// </summary>
public static class SampleAuthorization
{
    public static IServiceCollection AddSampleAuthorization(this IServiceCollection services, IConfiguration configuration)
    {
        var administrators = configuration.GetSection("Sample:Administrators").Get<string[]>() ?? [];
        services.AddAuthorization(options =>
        {
            foreach (var operation in IdentityOperations.All)
            {
                options.AddPolicy(operation.ToString(), policy => policy
                    .RequireAuthenticatedUser()
                    .RequireAssertion(context => IsAdministrator(context.User, administrators)));
            }
            foreach (var operation in IssuerOperations.All)
            {
                options.AddPolicy(operation.ToString(), policy => policy
                    .RequireAuthenticatedUser()
                    .RequireAssertion(context => IsAdministrator(context.User, administrators) || HoldsScope(context.User, IssuerModule.Name)));
            }
        });
        return services;
    }

    private static bool IsAdministrator(ClaimsPrincipal user, string[] administrators)
    {
        var email = user.FindFirstValue("email") ?? user.FindFirstValue(ClaimTypes.Email);
        return email is not null && administrators.Contains(email, StringComparer.OrdinalIgnoreCase);
    }

    private static bool HoldsScope(ClaimsPrincipal user, string scope)
        => user.FindAll("scope").Any(claim => claim.Value == scope);
}
