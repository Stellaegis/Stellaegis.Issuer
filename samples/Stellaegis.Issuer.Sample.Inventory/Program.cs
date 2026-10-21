// The example host of Stellaegis.Issuer, second of two processes: a resource server apart from the issuer. It
// holds no account and no OpenIddict; it takes Stellaegis.Issuer.Client alone, and with it accepts the bearer
// tokens the issuer issued for its module, refuses the revoked ones at the door, and speaks to the issuer with
// its own credentials — the ones the installation of the first process provisioned.
//
//   dotnet run
//       serves; the first process, Stellaegis.Issuer.Sample.Identity, must be running and installed.
//
// What a real host adds is its own: its modules and their data, its rights system answering the policies named
// after the operations.

using Stellaegis.Issuer.Client;
using Stellaegis.Issuer.Sample.Inventory;
using Stellaegis.Primitives;
using Stellaegis.Primitives.AspNetCore;
using Stellaegis.Primitives.Hosting;

var builder = WebApplication.CreateBuilder(args);

// The frame: one compartment, the company, and the request context its module reads — the actor is the sub of
// the bearer token, which the issuer wrote as the person's id or the service's client id.
builder.Services.AddStellaegisFrame(ApplicationFrame.SingleCompartment(Compartment.Parse("acme")));
builder.Services.AddStellaegisRequestContext();
builder.Services.AddStellaegisModule(InventoryModule.Declaration);

// What a resource server takes of the issuer: the bearer (Stellaegis:Issuer:Bearer — the issuer as authority, this
// host's module as audience), the admission of the revoked tokens read from the issuer's route over HTTP
// (Stellaegis:Issuer:Admission, Stellaegis:Issuer:Client), and its own credentials, with which it reads that route
// and calls the issuer (Stellaegis:Issuer:M2M).
builder.Services.AddStellaegisBearer(builder.Configuration);
builder.Services.AddStellaegisIssuerM2M(builder.Configuration);
builder.Services.AddStellaegisIssuerClient(builder.Configuration);
builder.Services.AddStellaegisIssuerAdmission(builder.Configuration);

// A client of the issuer's administration routes, this host's token for the scope "issuer" attached to every
// request: what the catalog route below reads the scopes with.
builder.Services.AddHttpClient(InventoryEndpoints.IssuerClient, http =>
        http.BaseAddress = new Uri(builder.Configuration["Stellaegis:Issuer:Client:BaseUrl"]!.TrimEnd('/') + "/"))
    .AddM2MToken("issuer");

// Who may call: a token carrying the scope of this module, whoever its subject is — a person through the desktop,
// a service with the credentials the installation gave it. A real host answers from its rights system.
builder.Services.AddAuthorization(options =>
{
    foreach (var operation in InventoryOperations.All)
        options.AddPolicy(operation.ToString(), policy => policy.RequireAuthenticatedUser().RequireClaim("scope", InventoryModule.Name));
});

var app = builder.Build();

app.UseAuthentication();
app.UseStellaegisActorAdmission();   // of Primitives: the revoked tokens, and any other admission registered
app.UseAuthorization();

app.MapGroup("/api")
    .MapInventoryEndpoints()
    .RequireAuthorizationPerOperation(operation => operation.ToString());

app.Run();
