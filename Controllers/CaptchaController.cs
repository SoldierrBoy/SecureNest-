using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SecureAccountsLab6.Services;

namespace SecureAccountsLab6.Controllers;

public sealed class CaptchaController(CaptchaService captcha) : Controller
{
    [HttpGet("captcha/image")]
    [EnableRateLimiting("captcha")]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public IActionResult Image()
    {
        Response.Headers.CacheControl = "no-store, no-cache, must-revalidate";
        return Content(captcha.GenerateSvg(HttpContext.Session), "image/svg+xml; charset=utf-8");
    }
}
