using SecureAccountsLab6.Data;
using SecureAccountsLab6.Models;

namespace SecureAccountsLab6.Services;

public sealed class AuditService(AppDbContext db, IHttpContextAccessor accessor)
{
    public async Task LogAsync(string? email, string result, AppUser? user = null)
    {
        var context = accessor.HttpContext;
        var normalizedEmail = (email ?? "").Trim().ToLowerInvariant();
        var agent = context?.Request.Headers.UserAgent.ToString() ?? "";
        db.LoginAudits.Add(new LoginAudit
        {
            UserId = user?.Id,
            Email = normalizedEmail[..Math.Min(normalizedEmail.Length, 256)],
            Result = result,
            IpAddress = context?.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            UserAgent = agent[..Math.Min(agent.Length, 256)]
        });
        await db.SaveChangesAsync();
    }
}
