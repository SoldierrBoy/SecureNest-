using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SecureAccountsLab6.Models;

namespace SecureAccountsLab6.Data;

public static class SeedData
{
    public static async Task InitializeAsync(IServiceProvider services, bool development, bool resetAdmin)
    {
        using var scope = services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        await db.Database.EnsureCreatedAsync(); // Local teaching project; use EF migrations for production evolution.
        var roles = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        foreach (var role in new[] { "User", "Admin" })
            if (!await roles.RoleExistsAsync(role))
                await roles.CreateAsync(new IdentityRole(role));

        if (!development) return;
        var users = scope.ServiceProvider.GetRequiredService<UserManager<AppUser>>();
        const string email = "admin@lab.local";
        var admin = await users.FindByEmailAsync(email);
        if (admin is not null && !resetAdmin) return;

        // A fresh, unpredictable password: no shared default credentials.
        var password = "A!9a" + Convert.ToHexString(RandomNumberGenerator.GetBytes(18));
        if (admin is null)
        {
            admin = new AppUser
            {
                UserName = email, Email = email, EmailConfirmed = true,
                DisplayName = "Адміністратор", CreatedAtUtc = DateTime.UtcNow
            };
            var created = await users.CreateAsync(admin, password);
            if (!created.Succeeded)
                throw new InvalidOperationException(string.Join("; ", created.Errors.Select(e => e.Description)));
            await users.AddToRoleAsync(admin, "Admin");
        }
        else
        {
            var token = await users.GeneratePasswordResetTokenAsync(admin);
            var result = await users.ResetPasswordAsync(admin, token, password);
            if (!result.Succeeded) throw new InvalidOperationException("Не вдалося змінити пароль демо-адміністратора.");
            admin.IsBlocked = false;
            admin.LockoutEnd = null;
            admin.AccessFailedCount = 0;
            await users.UpdateAsync(admin);
        }
        Console.WriteLine("\n==============================================");
        Console.WriteLine("LOCAL DEMO ADMIN — SAVE THESE CREDENTIALS:");
        Console.WriteLine($"EMAIL:    {email}");
        Console.WriteLine($"PASSWORD: {password}");
        Console.WriteLine("==============================================\n");
    }
}
