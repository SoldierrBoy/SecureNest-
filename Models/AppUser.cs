using Microsoft.AspNetCore.Identity;

namespace SecureAccountsLab6.Models;

public sealed class AppUser : IdentityUser
{
    public string DisplayName { get; set; } = "";
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? LastLoginUtc { get; set; }
    public bool IsBlocked { get; set; }
}
