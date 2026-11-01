using System.Net;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SecureAccountsLab6.Data;

namespace SecureAccountsLab6.Controllers;

[Route("dev/mail")]
[AllowAnonymous]
public sealed class DevMailController(AppDbContext db, IWebHostEnvironment environment) : Controller
{
    [HttpGet("")]
    public async Task<IActionResult> Index()
    {
        if (!IsAllowed()) return NotFound();
        var messages = await db.DevMails.AsNoTracking().OrderByDescending(x => x.Id).Take(100).ToListAsync();
        return View(messages);
    }

    private bool IsAllowed()
    {
        var remote = HttpContext.Connection.RemoteIpAddress;
        return environment.IsDevelopment() && remote is not null && IPAddress.IsLoopback(remote);
    }
}
