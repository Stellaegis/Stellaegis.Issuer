using System.Globalization;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Options;

namespace Stellaegis.Issuer.Server;

/// <summary>The type the resource files of the page are named after: <c>IssuerPagesResources.resx</c> in English, <c>IssuerPagesResources.fr.resx</c> in French.</summary>
public sealed class IssuerPagesResources
{
    private IssuerPagesResources()
    {
    }
}

/// <summary>
/// The texts of the page, in the culture of the request: what <see cref="IssuerPagesOptions.Texts"/> replaced
/// first, the resources of the package otherwise. The page reads <c>T["Sessions.Title"]</c>.
/// </summary>
internal sealed class IssuerTexts(IStringLocalizer<IssuerPagesResources> localizer, IOptions<IssuerPagesOptions> options)
{
    /// <summary>The text of <paramref name="key"/>, or the key itself when no resource has it.</summary>
    public string this[string key] => Find(key) ?? key;

    /// <summary>The text of <paramref name="key"/> with <paramref name="arguments"/> formatted in.</summary>
    public string Format(string key, params object[] arguments)
        => string.Format(CultureInfo.CurrentCulture, this[key], arguments);

    private string? Find(string key)
    {
        var overrides = options.Value.Texts;
        var culture = CultureInfo.CurrentUICulture;
        if (Overridden(overrides, culture.Name, key) is { } exact)
            return exact;
        if (culture.Name != culture.TwoLetterISOLanguageName && Overridden(overrides, culture.TwoLetterISOLanguageName, key) is { } language)
            return language;
        if (Overridden(overrides, "*", key) is { } any)
            return any;
        var localized = localizer[key];
        return localized.ResourceNotFound ? null : localized.Value;
    }

    private static string? Overridden(Dictionary<string, Dictionary<string, string>> overrides, string culture, string key)
        => overrides.TryGetValue(culture, out var texts) && texts.TryGetValue(key, out var text) ? text : null;
}
