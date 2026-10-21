using System.Globalization;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Issuer.Server;

/// <summary>
/// What the sessions page shows of the application, bound from <see cref="SectionName"/> or configured in code,
/// and validated when the host starts. The page is made the host's own the way the pages of Stellaegis.Identity
/// are, from the lightest gesture to the heaviest:
/// <list type="number">
/// <item><description><b>Options</b>: the name of the application, the culture, here.</description></item>
/// <item><description><b>Texts</b>: every text of the page is a resource, in English and in French; <see cref="Texts"/>
/// replaces one or several of them per culture, from the configuration.</description></item>
/// <item><description><b>Styles</b>: the stylesheet of the package is built on the CSS variables of the pages of
/// Stellaegis.Identity, so one stylesheet restyles both; a host names its own in <see cref="StylesheetPath"/>,
/// or serves its own file at the same path, which wins over the package's.</description></item>
/// <item><description><b>Layout and page</b>: the page renders inside <c>_AccountLayout</c> when the host or
/// Stellaegis.Identity.Server provides one — it then sits among the account pages, and the host adds the link to
/// it in its own <c>Pages/Shared/_AccountLayout.cshtml</c> —, inside the package's own layout otherwise. A host
/// that places <c>Pages/Account/Sessions.cshtml</c> at the same path replaces the page.</description></item>
/// </list>
/// <code>
/// Stellaegis:Issuer:Pages:ApplicationName = Durand SA
/// Stellaegis:Issuer:Pages:Culture = fr
/// </code>
/// </summary>
public sealed class IssuerPagesOptions : IValidatableOptions
{
    /// <summary>The configuration section of the page.</summary>
    public const string SectionName = "Stellaegis:Issuer:Pages";

    /// <summary>Where the stylesheet of the package is served from.</summary>
    public const string ContentPath = "/_content/Stellaegis.Issuer.Server";

    /// <summary>The name of the application, shown by the package's own layout. Required.</summary>
    public string ApplicationName { get; set; } = "Stellaegis";

    /// <summary>The stylesheet of the package's own layout — the package's unless set. Unused when the page renders inside the account layout of the host.</summary>
    public string StylesheetPath { get; set; } = ContentPath + "/issuer.css";

    /// <summary>
    /// The culture of the page, <c>fr</c> or <c>en-GB</c>: the texts and the dates follow it. Unless set, the page
    /// follows the culture of the request, which the host's request localization decides, or the culture of the
    /// process when the host decides nothing.
    /// </summary>
    public string? Culture { get; set; }

    /// <summary>The name of a rate limiting policy of the host applied to the page, which the host registers and enables itself. None unless set.</summary>
    public string? RateLimitingPolicy { get; set; }

    /// <summary>Where a person is sent after ending every session, signed out of the host: <c>/</c> unless set.</summary>
    public string AfterRevokeAllPath { get; set; } = "/";

    /// <summary>
    /// Texts replaced per culture, keyed by the culture then by the key of the text, which the resource files of
    /// the package list: <c>Texts:fr:Sessions.Title</c>. The culture <c>*</c> applies to every culture.
    /// </summary>
    public Dictionary<string, Dictionary<string, string>> Texts { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <inheritdoc/>
    public string? FindError()
    {
        if (string.IsNullOrWhiteSpace(ApplicationName))
            return $"{nameof(ApplicationName)} is required.";
        if (string.IsNullOrWhiteSpace(StylesheetPath) || !IsPath(StylesheetPath))
            return $"{nameof(StylesheetPath)} must be an absolute path or an http(s) URL.";
        if (!string.IsNullOrEmpty(Culture) && !IsCulture(Culture))
            return $"{nameof(Culture)} must name a known culture, such as fr or en-GB.";
        if (RateLimitingPolicy is not null && string.IsNullOrWhiteSpace(RateLimitingPolicy))
            return $"{nameof(RateLimitingPolicy)} must name a policy, or be absent.";
        if (string.IsNullOrWhiteSpace(AfterRevokeAllPath) || !AfterRevokeAllPath.StartsWith('/') || AfterRevokeAllPath.StartsWith("//", StringComparison.Ordinal))
            return $"{nameof(AfterRevokeAllPath)} must be a local path.";
        return null;
    }

    private static bool IsPath(string value)
        => value.StartsWith('/') && !value.StartsWith("//", StringComparison.Ordinal)
        || Uri.TryCreate(value, UriKind.Absolute, out var uri) && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps);

    private static bool IsCulture(string name)
    {
        try
        {
            return !string.IsNullOrEmpty(CultureInfo.GetCultureInfo(name, predefinedOnly: true).Name);
        }
        catch (CultureNotFoundException)
        {
            return false;
        }
    }
}
