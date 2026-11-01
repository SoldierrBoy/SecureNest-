using System.ComponentModel.DataAnnotations;

namespace SecureAccountsLab6.Models;

public sealed class DevMail
{
    public long Id { get; set; }
    [MaxLength(256)] public string Recipient { get; set; } = "";
    [MaxLength(150)] public string Subject { get; set; } = "";
    [MaxLength(40)] public string Category { get; set; } = "";
    public string ActionUrl { get; set; } = "";
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
}
