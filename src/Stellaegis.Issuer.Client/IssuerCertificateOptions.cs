using System.Security.Cryptography.X509Certificates;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Issuer.Client;

/// <summary>
/// One certificate, as the issuer signs and encrypts with and as a resource server decrypts with: a PKCS #12 file
/// and its password, or a thumbprint in the current user's personal store.
/// </summary>
public sealed class IssuerCertificateOptions : IValidatableOptions
{
    /// <summary>The path of the PKCS #12 file.</summary>
    public string? Path { get; set; }

    /// <summary>The password of the PKCS #12 file, from a secret store.</summary>
    public string? Password { get; set; }

    /// <summary>The thumbprint of the certificate in the current user's personal store, instead of a file.</summary>
    public string? Thumbprint { get; set; }

    /// <summary>Whether the options name a certificate at all.</summary>
    public bool IsSet => !string.IsNullOrWhiteSpace(Path) || !string.IsNullOrWhiteSpace(Thumbprint);

    /// <inheritdoc/>
    public string? FindError()
    {
        if (!string.IsNullOrWhiteSpace(Path) && !string.IsNullOrWhiteSpace(Thumbprint))
            return $"{nameof(Path)} and {nameof(Thumbprint)} are exclusive: one certificate comes from a file or from the store.";
        if (string.IsNullOrWhiteSpace(Path) && Password is not null)
            return $"{nameof(Password)} goes with {nameof(Path)}.";
        return null;
    }

    /// <summary>Loads the certificate the options name, with its private key.</summary>
    /// <exception cref="InvalidOperationException">The options name none, or the store holds none with that thumbprint.</exception>
    public X509Certificate2 Load()
    {
        if (!string.IsNullOrWhiteSpace(Path))
            return X509CertificateLoader.LoadPkcs12FromFile(Path, Password);
        if (string.IsNullOrWhiteSpace(Thumbprint))
            throw new InvalidOperationException("No certificate is named: set Path, or Thumbprint.");

        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        var found = store.Certificates.Find(X509FindType.FindByThumbprint, Thumbprint, validOnly: false);
        return found.Count > 0
            ? found[0]
            : throw new InvalidOperationException($"No certificate with the thumbprint {Thumbprint} in the current user's personal store.");
    }
}
