using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SecureAccountsLab6.Data;
using SecureAccountsLab6.Models;
using SecureAccountsLab6.ViewModels;

namespace SecureAccountsLab6.Controllers;

[Authorize(Roles = "Admin")]
[Route("admin")]
public sealed class AdminController(AppDbContext db, UserManager<AppUser> users) : Controller
{
    [HttpGet("")]
    public async Task<IActionResult> Index(string? q, int page = 1)
    {
        page = Math.Clamp(page, 1, 10000);
        var query = db.Users.AsNoTracking().AsQueryable();
        if (!string.IsNullOrWhiteSpace(q))
        {
            var search = q.Trim().ToLower();
            query = query.Where(u => u.Email != null && u.Email.ToLower().Contains(search));
        }
        var matchedCount = await query.CountAsync();
        var items = await query.OrderByDescending(u => u.CreatedAtUtc)
            .Skip((page - 1) * 40).Take(40).ToListAsync();
        var failedAttempts = await db.LoginAudits.AsNoTracking()
            .Where(a => a.Result.StartsWith("FAILED") || a.Result.StartsWith("LOCKED"))
            .GroupBy(a => a.Email)
            .Select(g => new { Email = g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.Email, x => x.Count);
        var results = new List<AdminUserVm>();
        foreach (var u in items)
        {
            failedAttempts.TryGetValue(u.Email?.ToLowerInvariant() ?? "", out var count);
            results.Add(new AdminUserVm
            {
                User = u,
                IsAdmin = await users.IsInRoleAsync(u, "Admin"),
                FailedAttempts = count
            });
        }
        ViewBag.Query = q;
        ViewBag.Page = page;
        ViewBag.PageCount = Math.Max(1, (int)Math.Ceiling(matchedCount / 40.0));
        ViewBag.UserCount = await db.Users.CountAsync();
        ViewBag.UnconfirmedCount = await db.Users.CountAsync(u => !u.EmailConfirmed);
        ViewBag.BlockedCount = await db.Users.CountAsync(u => u.IsBlocked);
        ViewBag.FailCount = await db.LoginAudits.CountAsync(a => a.Result.StartsWith("FAILED") || a.Result.StartsWith("LOCKED"));
        return View(results);
    }

    [HttpPost("block/{id}")]
    public async Task<IActionResult> Block(string id)
    {
        var user = await users.FindByIdAsync(id);
        if (user is null) return NotFound();
        if (user.Id == users.GetUserId(User) || await users.IsInRoleAsync(user, "Admin"))
        {
            TempData["Warning"] = "Адміністратора блокувати не можна.";
            return RedirectToAction(nameof(Index));
        }
        user.IsBlocked = true;
        await users.UpdateAsync(user);
        await users.UpdateSecurityStampAsync(user); // revoke authenticated cookies
        TempData["Success"] = $"Користувача {user.Email} заблоковано.";
        return RedirectToAction(nameof(Index));
    }

    [HttpPost("unblock/{id}")]
    public async Task<IActionResult> Unblock(string id)
    {
        var user = await users.FindByIdAsync(id);
        if (user is null) return NotFound();
        if (await users.IsInRoleAsync(user, "Admin")) return Forbid();
        user.IsBlocked = false;
        user.LockoutEnd = null;
        user.AccessFailedCount = 0;
        await users.UpdateAsync(user);
        await users.UpdateSecurityStampAsync(user);
        TempData["Success"] = $"Користувача {user.Email} розблоковано.";
        return RedirectToAction(nameof(Index));
    }

    [HttpGet("logs")]
    public async Task<IActionResult> Logs(string? email, int page = 1)
    {
        page = Math.Clamp(page, 1, 1000);
        var query = db.LoginAudits.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(email))
        {
            var search = email.Trim().ToLower();
            query = query.Where(a => a.Email.Contains(search));
        }
        var total = await query.CountAsync();
        var logs = await query.OrderByDescending(x => x.OccurredUtc).ThenByDescending(x => x.Id)
            .Skip((page - 1) * 40).Take(40).ToListAsync();
        var last500 = await db.LoginAudits.AsNoTracking().OrderByDescending(x => x.Id).Take(500).ToListAsync();
        var attemptCounts = last500.GroupBy(x => x.Email).Select(g => new AttemptCountVm
        {
            Email = g.Key,
            Total = g.Count(),
            Failed = g.Count(a => a.Result.StartsWith("FAILED") || a.Result.StartsWith("LOCKED"))
        }).OrderByDescending(x => x.Failed).ThenByDescending(x => x.Total).Take(10).ToList();
        return View(new AdminLogsVm { Logs = logs, Page = page, Total = total, Filter = email, Attempts = attemptCounts });
    }
}
