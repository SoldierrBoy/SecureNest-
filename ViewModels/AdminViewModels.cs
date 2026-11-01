using SecureAccountsLab6.Models;

namespace SecureAccountsLab6.ViewModels;

public sealed class AdminUserVm
{
    public required AppUser User { get; init; }
    public bool IsAdmin { get; init; }
    public int FailedAttempts { get; init; }
}

public sealed class AttemptCountVm
{
    public string Email { get; set; } = "";
    public int Total { get; set; }
    public int Failed { get; set; }
}

public sealed class AdminLogsVm
{
    public IReadOnlyList<LoginAudit> Logs { get; set; } = [];
    public IReadOnlyList<AttemptCountVm> Attempts { get; set; } = [];
    public int Total { get; set; }
    public int Page { get; set; }
    public string? Filter { get; set; }
}
