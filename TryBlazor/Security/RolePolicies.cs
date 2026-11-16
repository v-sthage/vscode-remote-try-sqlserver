using System.Security.Claims;

namespace TryBlazor.Security;

public static class RolePolicies
{
    public const string BeoAccess = "BeoAccess";
    public const string StandardAccess = "StandardAccess";
    public const string UserManagement = "UserManagement";

    public static bool HasBeoAccess(ClaimsPrincipal user)
    {
        return TryGetRole(user, out var role) && (role == 0 || role >= 2);
    }

    public static bool HasMinimumRole(ClaimsPrincipal user, int minimumRole)
    {
        return TryGetRole(user, out var role) && role >= minimumRole;
    }

    private static bool TryGetRole(ClaimsPrincipal user, out int role)
    {
        return int.TryParse(user.FindFirst(ClaimTypes.Role)?.Value, out role);
    }
}
