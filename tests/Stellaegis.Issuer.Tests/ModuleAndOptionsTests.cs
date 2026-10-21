using Microsoft.AspNetCore.Builder;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Stellaegis.Issuer.Client;
using Stellaegis.Primitives;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Issuer.Tests;

/// <summary>What the module declares, and what the options refuse.</summary>
public sealed class ModuleAndOptionsTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public void The_module_has_no_compartments_and_fits_every_frame()
    {
        ApplicationFrame.WithoutCompartments.Validate([IssuerModule.Declaration]);
        ApplicationFrame.SingleCompartment("acme").Validate([IssuerModule.Declaration]);
        ApplicationFrame.ManyCompartments().WithSharedSpace().Validate([IssuerModule.Declaration]);

        Assert.Equal("issuer", IssuerModule.Name);
        Assert.Equal(ModuleCompartments.None, IssuerModule.Declaration.Compartments);
        Assert.False(IssuerModule.Declaration.AcceptsSharedSpace);
        Assert.Equal(["clients.read", "clients.write", "clients.delete", "scopes.read", "scopes.write", "scopes.delete", "tokens.revoke"], IssuerModule.Declaration.Operations.Select(o => o.Identity));
        Assert.Equal(IssuerModule.Declaration.Operations, IssuerOperations.All);
    }

    [Fact]
    public async Task The_host_declares_the_module_once_and_publishes_nothing_without_a_bus()
    {
        await using var app = await IssuerTestHost.Builder().StartAsync(Ct);
        var declared = Assert.Single(app.Services.GetStellaegisModules(), module => module.Name == "issuer");
        Assert.Equal(IssuerModule.Declaration, declared);

        var services = new ServiceCollection().AddLogging().AddStellaegisFrame(ApplicationFrame.WithoutCompartments);
        services.AddStellaegisIssuer(o => o.Certificates.UseDevelopmentCertificates = true, db => db.UseSqlite("Data Source=:memory:"));
        services.AddStellaegisIssuer(o => o.Certificates.UseDevelopmentCertificates = true, db => db.UseSqlite("Data Source=:memory:"));
        using var provider = services.BuildServiceProvider();
        Assert.Single(provider.GetStellaegisModules(), module => module.Name == "issuer");
        Assert.IsType<NullEventPublisher>(provider.GetRequiredService<IEventPublisher>());
    }

    [Theory]
    [InlineData("lifetime")]
    [InlineData("issuer")]
    [InlineData("redirect")]
    [InlineData("certificate")]
    public void Options_that_do_not_hold_are_refused_at_registration(string what)
    {
        var services = new ServiceCollection();
        var exception = Assert.Throws<InvalidOperationException>(() => services.AddStellaegisIssuer(options =>
        {
            options.Certificates.UseDevelopmentCertificates = true;
            switch (what)
            {
                case "lifetime": options.AccessTokenLifetime = TimeSpan.Zero; break;
                case "issuer": options.Issuer = "id.acme.example"; break;
                case "redirect": options.Clients["x"] = new ConfiguredClientOptions { RedirectUris = ["nope"] }; break;
                case "certificate": options.Certificates.Signing = new IssuerCertificateOptions { Path = "a.pfx", Thumbprint = "ABC" }; break;
            }
        }, db => db.UseSqlite("Data Source=:memory:")));
        Assert.StartsWith("IssuerOptions:", exception.Message);
    }

    [Fact]
    public async Task Outside_development_the_development_certificates_are_refused_and_real_ones_are_required()
    {
        var builder = IssuerTestHost.Builder(environment: Environments.Production);
        var app = builder.Build();
        var exception = await Assert.ThrowsAsync<OptionsValidationException>(() => app.StartAsync(Ct));
        Assert.Contains("UseDevelopmentCertificates", exception.Message);
        await app.DisposeAsync();

        var missing = IssuerTestHost.Builder(options => options.Certificates.UseDevelopmentCertificates = false, environment: Environments.Production).Build();
        var required = await Assert.ThrowsAsync<OptionsValidationException>(() => missing.StartAsync(Ct));
        Assert.Contains("Signing", required.Message);
        await missing.DisposeAsync();
    }
}
