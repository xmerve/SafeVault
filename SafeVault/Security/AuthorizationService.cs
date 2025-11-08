namespace SafeVault.Security;

public static class AuthorizationService
{
    public static bool Authorize(UserPrincipal? principal, params string[] requiredRoles)
    {
        if (principal is null)
        {
            return false;
        }

        if (requiredRoles is null || requiredRoles.Length == 0)
        {
            return true;
        }

        return requiredRoles.Any(role =>
            string.Equals(principal.Value.Role, role, StringComparison.OrdinalIgnoreCase));
    }
}

