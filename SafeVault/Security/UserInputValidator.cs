using System.Collections.ObjectModel;

namespace SafeVault.Security;

/// <summary>
/// Performs validation over composite user input payloads, using <see cref="InputSanitizer"/>
/// to guard against injection attempts and to normalise values before persistence.
/// </summary>
public class UserInputValidator
{
    public ValidationResult ValidateRegistration(string? username, string? email) =>
        ValidateRegistration(username, email, password: null);

    public ValidationResult ValidateRegistration(string? username, string? email, string? password)
    {
        var errors = new List<string>();

        if (!InputSanitizer.IsValidUsername(username))
        {
            errors.Add("Username must be 3-30 characters and may contain letters, digits, ., _, or -.");
        }

        if (!InputSanitizer.IsValidEmail(email))
        {
            errors.Add("Email address is not valid.");
        }

        if (password is not null && !IsPasswordStrong(password))
        {
            errors.Add("Password must be at least 12 characters and include upper, lower, digit, and symbol.");
        }

        var safeUsername = InputSanitizer.SanitizeForHtml(username);
        var safeEmail = InputSanitizer.SanitizeForHtml(InputSanitizer.NormaliseEmail(email));

        return errors.Count switch
        {
            0 => ValidationResult.Success(safeUsername, safeEmail),
            _ => ValidationResult.Failure(errors)
        };
    }

    public bool IsPasswordStrong(string? password)
    {
        if (string.IsNullOrWhiteSpace(password) || password.Length < 12)
        {
            return false;
        }

        var hasUpper = password.Any(char.IsUpper);
        var hasLower = password.Any(char.IsLower);
        var hasDigit = password.Any(char.IsDigit);
        var hasSymbol = password.Any(c => !char.IsLetterOrDigit(c));

        return hasUpper && hasLower && hasDigit && hasSymbol;
    }
}

public record ValidationResult(bool IsValid, string SanitizedUsername, string SanitizedEmail, IReadOnlyCollection<string> Errors)
{
    public static ValidationResult Success(string username, string email) =>
        new(true, username, email, new ReadOnlyCollection<string>(Array.Empty<string>()));

    public static ValidationResult Failure(IEnumerable<string> errors) =>
        new(false, string.Empty, string.Empty, new ReadOnlyCollection<string>(errors.ToList()));
}

