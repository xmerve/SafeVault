using BCrypt.Net;
using SafeVault.Data;

namespace SafeVault.Security;

public class AuthenticationService
{
    private static readonly HashSet<string> AllowedRoles = new(StringComparer.OrdinalIgnoreCase)
    {
        "admin",
        "user"
    };

    private readonly UserRepository _repository;
    private readonly UserInputValidator _validator;

    public AuthenticationService(UserRepository repository, UserInputValidator validator)
    {
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
        _validator = validator ?? throw new ArgumentNullException(nameof(validator));
    }

    public async Task<RegistrationResult> RegisterAsync(string username, string email, string password, string role)
    {
        if (!AllowedRoles.Contains(role))
        {
            return RegistrationResult.Failure($"Role '{role}' is not allowed.");
        }

        var validation = _validator.ValidateRegistration(username, email, password);
        if (!validation.IsValid)
        {
            return RegistrationResult.Failure(string.Join(" ", validation.Errors));
        }

        var existing = await _repository.GetUserByUsernameAsync(username);
        if (existing is not null)
        {
            return RegistrationResult.Failure("Username is already taken.");
        }

        var passwordHash = BCrypt.Net.BCrypt.EnhancedHashPassword(password, HashType.SHA512);
        var userId = await _repository.CreateUserAsync(validation.SanitizedUsername, validation.SanitizedEmail, passwordHash, role.ToLowerInvariant());

        return RegistrationResult.Success(new UserPrincipal(userId, validation.SanitizedUsername, validation.SanitizedEmail, role.ToLowerInvariant()));
    }

    public async Task<AuthenticationResult> AuthenticateAsync(string username, string password)
    {
        var user = await _repository.GetUserByUsernameAsync(username);
        if (user is null)
        {
            return AuthenticationResult.Failure("Invalid username or password.");
        }

        var verified = BCrypt.Net.BCrypt.EnhancedVerify(password, user.PasswordHash, HashType.SHA512);
        if (!verified)
        {
            return AuthenticationResult.Failure("Invalid username or password.");
        }

        var principal = new UserPrincipal(user.UserId, user.Username, user.Email, user.Role);
        return AuthenticationResult.Success(principal);
    }
}

public readonly record struct UserPrincipal(int UserId, string Username, string Email, string Role);

public record AuthenticationResult(bool IsAuthenticated, string Message, UserPrincipal? Principal)
{
    public static AuthenticationResult Success(UserPrincipal principal) =>
        new(true, "Authenticated", principal);

    public static AuthenticationResult Failure(string message) =>
        new(false, message, null);
}

public record RegistrationResult(bool Succeeded, string Message, UserPrincipal? Principal)
{
    public static RegistrationResult Success(UserPrincipal principal) =>
        new(true, "Registered", principal);

    public static RegistrationResult Failure(string message) =>
        new(false, message, null);
}

