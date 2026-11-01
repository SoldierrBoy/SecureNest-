using System.ComponentModel.DataAnnotations;

namespace SecureAccountsLab6.Models;

public sealed class LoginAudit
{
    public long Id { get; set; }
    [MaxLength(450)] public string? UserId { get; set; }
    [MaxLength(256)] public string Email { get; set; } = "";
    [MaxLength(64)] public string IpAddress { get; set; } = "";
    [MaxLength(256)] public string UserAgent { get; set; } = "";
    [MaxLength(48)] public string Result { get; set; } = "";
    public DateTime OccurredUtc { get; set; } = DateTime.UtcNow;
}
