using Stellaegis.Primitives;

namespace Stellaegis.Issuer;

/// <summary>
/// The errors the module answers its caller, each with the code that lets the caller recognize it: in process
/// through a failed <see cref="Result"/>, over HTTP through the <c>code</c> of the problem details. What the
/// protocol routes answer a client is OpenID Connect's — <c>invalid_grant</c>, <c>access_denied</c> —, not these.
/// </summary>
public static class IssuerErrors
{
    /// <summary>The code of <see cref="TokenRevoked"/>: the token the principal carries was revoked.</summary>
    public const string TokenRevokedCode = "Token.Revoked";

    /// <summary>The code of <see cref="TokenNotFound"/>: no token with that id.</summary>
    public const string TokenNotFoundCode = "Token.NotFound";

    /// <summary>The code of <see cref="SubjectMissing"/>: the authenticated principal carries no subject.</summary>
    public const string SubjectMissingCode = "Subject.Missing";

    /// <summary>The code of <see cref="ClientNotFound"/>: no client with that id.</summary>
    public const string ClientNotFoundCode = "Client.NotFound";

    /// <summary>The code of <see cref="ClientExists"/>: a client with that id exists already.</summary>
    public const string ClientExistsCode = "Client.Exists";

    /// <summary>The code of <see cref="ClientInvalid"/>: the client's definition does not hold.</summary>
    public const string ClientInvalidCode = "Client.Invalid";

    /// <summary>The code of <see cref="ScopeNotFound"/>: no scope with that name.</summary>
    public const string ScopeNotFoundCode = "Scope.NotFound";

    /// <summary>The code of <see cref="ScopeExists"/>: a scope with that name exists already.</summary>
    public const string ScopeExistsCode = "Scope.Exists";

    /// <summary>The code of <see cref="ScopeInvalid"/>: the scope's definition does not hold.</summary>
    public const string ScopeInvalidCode = "Scope.Invalid";

    /// <summary>The token the principal carries was revoked.</summary>
    public static Error TokenRevoked { get; } =
        Error.Unauthorized(TokenRevokedCode, "The token was revoked.");

    /// <summary>No token with that id.</summary>
    public static Error TokenNotFound { get; } =
        Error.NotFound(TokenNotFoundCode, "The token was not found.");

    /// <summary>The authenticated principal carries no subject: nothing to issue a token to.</summary>
    public static Error SubjectMissing { get; } =
        Error.Failure(SubjectMissingCode, "The authenticated user carries no subject claim: map the claim the host's authentication produces onto sub or NameIdentifier.");

    /// <summary>No client with that id.</summary>
    public static Error ClientNotFound { get; } =
        Error.NotFound(ClientNotFoundCode, "The client was not found.");

    /// <summary>A client with that id exists already.</summary>
    public static Error ClientExists { get; } =
        Error.Conflict(ClientExistsCode, "A client with this id exists already.");

    /// <summary>The client's definition does not hold; <paramref name="detail"/> says what.</summary>
    public static Error ClientInvalid(string detail) => Error.Validation(ClientInvalidCode, Guard.NotWhiteSpace(detail));

    /// <summary>No scope with that name.</summary>
    public static Error ScopeNotFound { get; } =
        Error.NotFound(ScopeNotFoundCode, "The scope was not found.");

    /// <summary>A scope with that name exists already.</summary>
    public static Error ScopeExists { get; } =
        Error.Conflict(ScopeExistsCode, "A scope with this name exists already.");

    /// <summary>The scope's definition does not hold; <paramref name="detail"/> says what.</summary>
    public static Error ScopeInvalid(string detail) => Error.Validation(ScopeInvalidCode, Guard.NotWhiteSpace(detail));
}
