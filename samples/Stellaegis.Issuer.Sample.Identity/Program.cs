// The example host of Stellaegis.Issuer, first of two processes: the accounts and the issuer together — an
// enterprise application, one compartment, the company itself — whose people sign in on the pages of
// Stellaegis.Identity, and whose issuer turns the signed-in person into tokens for a native client, and gives the
// services apart their credentials. The second process, Stellaegis.Issuer.Sample.Inventory, is a resource server
// that accepts those tokens.
//
//   dotnet run -- install --admin-email admin@acme.test --admin-password 'Correct-Horse-9'
//       creates the database and the application's role if missing, installs the ident and oidc schemas under
//       the administration connection, creates the first administrator, declares the public client of the
//       desktop and provisions the credentials of the inventory module — the gestures of the installation.
//   dotnet run
//       verifies the installation under the application's role, then serves.
//
// What a real host adds is its own: its API and its modules, its rights system answering the policies named
// after the operations, its messaging behind IIdentityMailer, its bus behind IEventPublisher.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Stellaegis.Identity;
using Stellaegis.Identity.AspNetCore;
using Stellaegis.Identity.PostgreSQL;
using Stellaegis.Identity.Server;
using Stellaegis.Issuer;
using Stellaegis.Issuer.Client;
using Stellaegis.Issuer.PostgreSQL;
using Stellaegis.Issuer.Sample.Identity;
using Stellaegis.Issuer.Server;
using Stellaegis.Primitives;
using Stellaegis.Primitives.AspNetCore;
using Stellaegis.Primitives.Data;
using Stellaegis.Primitives.Hosting;

if (args.Length > 0 && args[0] == "install")
    return await Install.RunAsync(args[1..]);

var builder = WebApplication.CreateBuilder(args);

// The frame: one compartment, the company. Neither the accounts nor the issuer have compartments and neither
// reads the request context; the host's own modules would.
builder.Services.AddStellaegisFrame(SampleFrame.Value);
builder.Services.AddStellaegisRequestContext();

// The accounts on PostgreSQL (Stellaegis:Identity:PostgreSQL, Stellaegis:Identity), the cookie a person signs in
// with, the pages (Stellaegis:Identity:Pages), the administration routes, and the admission of the blocked
// accounts, read from the local store (Stellaegis:Identity:Admission).
builder.Services.AddStellaegisIdentityPostgreSQL(builder.Configuration);
builder.Services.AddStellaegisIdentityCookie();
builder.Services.AddStellaegisIdentityPages(builder.Configuration);
builder.Services.AddStellaegisIdentityAdministration();
builder.Services.AddStellaegisLocalBlockedUsersSource();
builder.Services.AddStellaegisIdentityAdmission(builder.Configuration);

// The issuer on the same PostgreSQL (Stellaegis:Issuer:PostgreSQL, Stellaegis:Issuer): the flows, the clients and
// the scopes, the revocation; its administration routes; the admission of the revoked tokens, read from its own
// store (Stellaegis:Issuer:Admission); the sessions page (Stellaegis:Issuer:Pages).
builder.Services.AddStellaegisIssuerPostgreSQL(builder.Configuration);
builder.Services.AddStellaegisIssuerAdministration();
builder.Services.AddStellaegisIssuerAdmission(builder.Configuration);
builder.Services.AddStellaegisIssuerPages(builder.Configuration);

// This host is a resource server too: its administration routes are called by the services apart with the
// tokens it issues — the inventory reads the revoked tokens that way. The bearer validates against this very
// host (Stellaegis:Issuer:Bearer), and a policy scheme chooses: a bearer token names the bearer, anything else
// the cookie — a person on the pages, a service on the routes.
builder.Services.AddStellaegisBearer(builder.Configuration);
builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = SampleAuthentication.Scheme;
        options.DefaultAuthenticateScheme = SampleAuthentication.Scheme;
        options.DefaultChallengeScheme = SampleAuthentication.Scheme;
    })
    .AddPolicyScheme(SampleAuthentication.Scheme, SampleAuthentication.Scheme, scheme =>
        scheme.ForwardDefaultSelector = context =>
            context.Request.Headers.Authorization.ToString().StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
                ? JwtBearerDefaults.AuthenticationScheme
                : IdentityCookie.Scheme);

// What the host brings: the mailer the pages send with — here, the log —; the bus the modules publish on — here,
// one that applies a block to the admission at once and revokes every token of the blocked person —; and who
// may administer: the people named in Sample:Administrators, and the services holding the scope of the issuer.
builder.Services.AddSingleton<IIdentityMailer, LoggingMailer>();
builder.Services.AddSingleton<IEventPublisher, SampleEventPublisher>();
builder.Services.AddSampleAuthorization(builder.Configuration);

// The pages follow the culture of the request: French and English, French when the browser says nothing.
builder.Services.AddRequestLocalization(options => options
    .SetDefaultCulture("fr")
    .AddSupportedCultures("fr", "en")
    .AddSupportedUICultures("fr", "en"));

var app = builder.Build();

// The installation ran before, under another role: prove it, under this one, before serving anything.
await app.Services.VerifyStellaegisDatabasesAsync();

app.UseRequestLocalization();
app.MapStaticAssets();   // the stylesheets, scripts and logos of the two Razor class libraries
app.UseAuthentication();

// The door of Primitives: every admission registered — the blocked accounts, the revoked tokens — on every route
// but the issuer's protocol routes, which answer a refused person themselves, to the client, with access_denied.
app.UseWhen(context => !context.Request.Path.StartsWithSegments("/connect"), door => door.UseStellaegisActorAdmission());
app.UseAuthorization();

app.MapStellaegisIdentityPages();   // /login, /register, /account/… — and /account/sessions, the issuer's page among them
app.MapStellaegisIssuer();          // /connect/authorize, /connect/logout; /connect/token is OpenIddict's own
app.MapGroup("/api/admin")
    .MapIdentityAdminEndpoints()
    .RequireAuthorizationPerOperation(operation => operation.ToString());
app.MapGroup("/api/admin")
    .MapIssuerAdminEndpoints()
    .RequireAuthorizationPerOperation(operation => operation.ToString());

app.Run();
return 0;
