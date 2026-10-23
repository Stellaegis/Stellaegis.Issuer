using Microsoft.AspNetCore.Builder;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
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
    [InlineData("password")]
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
                case "certificate":
                    options.Certificates.UseDevelopmentCertificates = false;
                    options.Certificates.Signing = new IssuerCertificateOptions { Path = "a.pfx", Thumbprint = "ABC" };
                    break;
                case "password":
                    options.Certificates.UseDevelopmentCertificates = false;
                    options.Certificates.Signing = new IssuerCertificateOptions { Path = "", Password = "secret" };
                    break;
            }
        }, db => db.UseSqlite("Data Source=:memory:")));
        Assert.StartsWith("IssuerOptions:", exception.Message);
    }

    [Fact]
    public void The_empty_values_of_an_exhaustive_appsettings_are_absent()
    {
        // Every key shown, nothing set: what an exhaustive appsettings.json holds, and what a variable of the
        // environment set to nothing gives.
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Stellaegis:Issuer:Certificates:UseDevelopmentCertificates"] = "false",
            ["Stellaegis:Issuer:Certificates:Signing:Path"] = "",
            ["Stellaegis:Issuer:Certificates:Signing:Password"] = "",
            ["Stellaegis:Issuer:Certificates:Signing:Thumbprint"] = "",
            ["Stellaegis:Issuer:Certificates:Encryption:Path"] = "",
            ["Stellaegis:Issuer:Certificates:Encryption:Password"] = "",
            ["Stellaegis:Issuer:Certificates:Encryption:Thumbprint"] = "",
            ["Stellaegis:Issuer:Clients:reports:Secret"] = "",
        }).Build();
        var options = new IssuerOptions();
        configuration.GetSection(IssuerOptions.SectionName).Bind(options);

        Assert.Null(options.FindError());
        Assert.False(options.Certificates.Signing.IsSet);
        Assert.False(options.Certificates.Encryption.IsSet);
        Assert.Null(options.Clients["reports"].SecretOrNull);
    }

    [Fact]
    public void With_the_development_certificates_the_named_ones_are_neither_loaded_nor_checked()
    {
        // The placeholder of a development configuration: a password without its file, harmless since unused.
        var options = new IssuerOptions();
        options.Certificates.UseDevelopmentCertificates = true;
        options.Certificates.Signing = new IssuerCertificateOptions { Path = "", Password = "CHANGE_ME" };

        Assert.Null(options.FindError());
        new ServiceCollection().AddStellaegisIssuer(o =>
        {
            o.Certificates.UseDevelopmentCertificates = true;
            o.Certificates.Signing = new IssuerCertificateOptions { Password = "CHANGE_ME" };
        }, db => db.UseSqlite("Data Source=:memory:"));
    }

    [Fact]
    public async Task Outside_development_empty_certificates_are_missing_ones()
    {
        var empty = IssuerTestHost.Builder(options =>
        {
            options.Certificates.UseDevelopmentCertificates = false;
            options.Certificates.Signing = new IssuerCertificateOptions { Path = "", Password = "", Thumbprint = "" };
        }, environment: Environments.Production).Build();

        var exception = await Assert.ThrowsAsync<OptionsValidationException>(() => empty.StartAsync(Ct));
        Assert.Contains("Signing is required outside Development", exception.Message);
        await empty.DisposeAsync();
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
