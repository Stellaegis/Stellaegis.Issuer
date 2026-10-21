using System.Globalization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc.ApplicationModels;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Stellaegis.Primitives;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Issuer.Server;

/// <summary>Registers the sessions page.</summary>
public static class IssuerPagesServiceCollectionExtensions
{
    /// <summary>
    /// Registers the page of the package — Razor Pages, the antiforgery that comes with them, the localization,
    /// the texts — with <see cref="IssuerPagesOptions"/> bound from <paramref name="sectionName"/> and validated
    /// when the host starts. The issuer is registered apart:
    /// <code>
    /// builder.Services.AddStellaegisIssuerPostgreSQL(builder.Configuration);
    /// builder.Services.AddStellaegisIssuerPages(builder.Configuration);
    /// ...
    /// app.MapStaticAssets();   // the stylesheet of the page
    /// app.UseAuthentication();
    /// app.UseAuthorization();
    /// app.MapStellaegisIssuerPages();
    /// </code>
    /// A host with Razor Pages of its own, the pages of Stellaegis.Identity among them, calls <c>AddRazorPages</c>
    /// as usual; this call adds the package's page to them.
    /// </summary>
    public static IServiceCollection AddStellaegisIssuerPages(this IServiceCollection services, IConfiguration configuration, string sectionName = IssuerPagesOptions.SectionName)
    {
        Guard.NotNull(configuration);
        Guard.NotWhiteSpace(sectionName);
        services.AddStellaegisOptions<IssuerPagesOptions>(configuration, sectionName);
        return services.AddPages();
    }

    /// <summary>
    /// Registers the page of the package with its options configured in code; otherwise as
    /// <see cref="AddStellaegisIssuerPages(IServiceCollection, IConfiguration, string)"/>.
    /// </summary>
    public static IServiceCollection AddStellaegisIssuerPages(this IServiceCollection services, Action<IssuerPagesOptions> configure)
    {
        Guard.NotNull(configure);
        services.AddStellaegisOptions(configure);
        return services.AddPages();
    }

    private static IServiceCollection AddPages(this IServiceCollection services)
    {
        Guard.NotNull(services);
        services.AddLocalization();
        services.AddAuthorization();
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IssuerTexts>();
        services.AddRazorPages()
            .AddApplicationPart(typeof(IssuerPagesOptions).Assembly);
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IConfigureOptions<RazorPagesOptions>, IssuerPagesConventions>());
        return services;
    }
}

/// <summary>Maps the sessions page.</summary>
public static class IssuerPagesEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps the Razor Pages of the host, the package's among them — <c>/account/sessions</c>. It is the host's
    /// <c>MapRazorPages</c>, which maps the pages once however many times it is called: a host that maps the
    /// pages of Stellaegis.Identity with <c>MapStellaegisIdentityPages()</c> has this page mapped too.
    /// </summary>
    public static IEndpointConventionBuilder MapStellaegisIssuerPages(this IEndpointRouteBuilder endpoints)
    {
        Guard.NotNull(endpoints);
        return endpoints.MapRazorPages();
    }
}

/// <summary>
/// What the package asks of its own page, and of no other page of the host: the rate limiting policy named in the
/// options, and the culture it is read in.
/// </summary>
internal sealed class IssuerPagesConventions(IOptions<IssuerPagesOptions> options) : IConfigureOptions<RazorPagesOptions>
{
    public void Configure(RazorPagesOptions razorPages)
        => razorPages.Conventions.Add(new PagesConvention(options.Value));

    private sealed class PagesConvention(IssuerPagesOptions options) : IPageApplicationModelConvention
    {
        public void Apply(PageApplicationModel model)
        {
            if (model.PageType.Assembly != typeof(IssuerPagesOptions).Assembly)
                return;
            if (!string.IsNullOrWhiteSpace(options.RateLimitingPolicy))
                model.EndpointMetadata.Add(new EnableRateLimitingAttribute(options.RateLimitingPolicy));
            if (!string.IsNullOrEmpty(options.Culture))
                model.Filters.Add(new CultureFilter(CultureInfo.GetCultureInfo(options.Culture)));
        }
    }

    /// <summary>Reads the page in the culture the options name, whatever the host decided for the request: a resource filter, which wraps the handler and the rendering alike.</summary>
    private sealed class CultureFilter(CultureInfo culture) : IAsyncResourceFilter
    {
        public Task OnResourceExecutionAsync(ResourceExecutingContext context, ResourceExecutionDelegate next)
        {
            CultureInfo.CurrentCulture = culture;
            CultureInfo.CurrentUICulture = culture;
            return next();
        }
    }
}
