using System.Text.Encodings.Web;
using System.Text.RegularExpressions;

namespace SafeVault.Security;

/// <summary>
/// Provides reusable sanitisation and validation helpers to protect the SafeVault web application
/// against common input-driven attacks such as XSS and SQL injection.
/// </summary>
public static class InputSanitizer
{
    private static readonly Regex ScriptBlockRegex = new(
        @"<\s*script\b[^>]*>.*?<\s*/\s*script\s*>",
        RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.Singleline);

    private static readonly Regex LoneScriptTagRegex = new(
        @"<\s*/?\s*script\b[^>]*>",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex DangerousProtocolRegex = new(
        @"javascript\s*:",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex HtmlEventAttributeRegex = new(
        @"\s+on\w+\s*=\s*(['""]).*?\1",
        RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.Singleline);

    private static readonly Regex UsernameRegex = new(
        @"^[A-Za-z0-9_\-\.]{3,30}$",
        RegexOptions.Compiled);

    /// <summary>
    /// Removes script tags, dangerous HTML event attributes, trims whitespace and HTML-encodes
    /// the result to ensure it is safe to display within the UI.
    /// </summary>
    public static string SanitizeForHtml(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return string.Empty;
        }

        var trimmed = input.Trim();
        trimmed = ScriptBlockRegex.Replace(trimmed, string.Empty);
        trimmed = LoneScriptTagRegex.Replace(trimmed, string.Empty);
        trimmed = HtmlEventAttributeRegex.Replace(trimmed, string.Empty);
        trimmed = DangerousProtocolRegex.Replace(trimmed, string.Empty);

        return HtmlEncoder.Default.Encode(trimmed);
    }

    /// <summary>
    /// Ensures usernames adhere to a constrained allow-list to mitigate injection attempts.
    /// </summary>
    public static bool IsValidUsername(string? username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return false;
        }

        return UsernameRegex.IsMatch(username);
    }

    /// <summary>
    /// Performs basic canonicalisation to prevent bypass through whitespace or casing anomalies.
    /// </summary>
    public static string NormaliseEmail(string? email) =>
        email?.Trim().ToLowerInvariant() ?? string.Empty;

    /// <summary>
    /// Validates the structure of an email address using the <see cref="System.Net.Mail.MailAddress"/> parser.
    /// </summary>
    public static bool IsValidEmail(string? email)
    {
        var normalised = NormaliseEmail(email);
        if (string.IsNullOrWhiteSpace(normalised))
        {
            return false;
        }

        try
        {
            _ = new System.Net.Mail.MailAddress(normalised);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
