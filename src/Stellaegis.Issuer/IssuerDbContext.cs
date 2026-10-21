using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;

namespace Stellaegis.Issuer;

/// <summary>
/// The context of the OpenIddict stores — applications, authorizations, scopes, tokens —, under the schema
/// <see cref="Schema"/> with snake-case names: <c>oidc.applications</c>, <c>oidc.authorizations</c>,
/// <c>oidc.scopes</c>, <c>oidc.tokens</c>. EF Core serves at run time only: the schema is installed by the
/// scripts of <c>Stellaegis.Issuer.PostgreSQL</c>, never migrated by EF Core. The provider is the host's, or the
/// adapter's.
/// </summary>
public sealed class IssuerDbContext(DbContextOptions<IssuerDbContext> options) : DbContext(options)
{
    /// <summary>The schema of the issuer, <c>oidc</c>.</summary>
    public const string Schema = "oidc";

    /// <inheritdoc/>
    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.HasDefaultSchema(Schema);
        builder.UseOpenIddict();
        builder.Entity<OpenIddictEntityFrameworkCoreApplication>().ToTable("applications", Schema);
        builder.Entity<OpenIddictEntityFrameworkCoreAuthorization>().ToTable("authorizations", Schema);
        builder.Entity<OpenIddictEntityFrameworkCoreScope>().ToTable("scopes", Schema);
        builder.Entity<OpenIddictEntityFrameworkCoreToken>().ToTable("tokens", Schema);
    }
}
