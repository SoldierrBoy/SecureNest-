using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SecureAccountsLab6.Models;

namespace SecureAccountsLab6.Data;

public sealed class AppDbContext(DbContextOptions<AppDbContext> options) : IdentityDbContext<AppUser>(options)
{
    public DbSet<LoginAudit> LoginAudits => Set<LoginAudit>();
    public DbSet<DevMail> DevMails => Set<DevMail>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.Entity<LoginAudit>().HasIndex(a => a.OccurredUtc);
        builder.Entity<LoginAudit>().HasIndex(a => a.Email);
        builder.Entity<DevMail>().HasIndex(m => m.CreatedAtUtc);
    }
}
