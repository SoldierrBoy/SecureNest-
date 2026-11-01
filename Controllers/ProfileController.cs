using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SecureAccountsLab6.Models;
using SecureAccountsLab6.ViewModels;

namespace SecureAccountsLab6.Controllers;

[Authorize]
[Route("profile")]
public sealed class ProfileController(UserManager<AppUser> users, SignInManager<AppUser> signIn, IConfiguration config) : Controller
{
    [HttpGet("")]
    public async Task<IActionResult> Index()
    {
        var user = await users.GetUserAsync(User);
        if (user is null || user.IsBlocked) return RedirectToAction("Login", "Auth");
        ViewBag.Roles = await users.GetRolesAsync(user);
        ViewBag.Logins = await users.GetLoginsAsync(user);
        return View(user);
    }

    [HttpGet("2fa")]
    public async Task<IActionResult> TwoFactor()
    {
        var user = await users.GetUserAsync(User);
        if (user is null) return Challenge();
        if (!await users.GetTwoFactorEnabledAsync(user) && await users.GetAuthenticatorKeyAsync(user) is null)
        {
            await users.ResetAuthenticatorKeyAsync(user);
            // ResetAuthenticatorKey rotates the security stamp: keep the current session valid.
            await signIn.RefreshSignInAsync(user);
        }
        var key = await users.GetAuthenticatorKeyAsync(user) ?? "";
        var normalized = string.Join(" ", Enumerable.Range(0, (key.Length + 3) / 4)
            .Select(i => key.Substring(i * 4, Math.Min(4, key.Length - i * 4))));
        return View(new TwoFactorSetupVm
        {
            Enabled = await users.GetTwoFactorEnabledAsync(user),
            SharedKey = normalized,
            AuthenticatorUri = $"otpauth://totp/SecureAccounts:{Uri.EscapeDataString(user.Email ?? "")}?secret={Uri.EscapeDataString(key)}&issuer=SecureAccounts&digits=6"
        });
    }

    [HttpPost("enable-2fa")]
    [EnableRateLimiting("twofactor")]
    public async Task<IActionResult> EnableTwoFactor(TwoFactorSetupVm model)
    {
        var user = await users.GetUserAsync(User);
        if (user is null) return Challenge();
        if (await users.GetTwoFactorEnabledAsync(user)) return RedirectToAction(nameof(TwoFactor));
        var code = (model.Code ?? "").Replace(" ", "").Replace("-", "");
        if (code.Length != 6 || !await users.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultAuthenticatorProvider, code))
        {
            TempData["Warning"] = "Код неправильний. Перевірте час на телефоні та спробуйте ще раз.";
            return RedirectToAction(nameof(TwoFactor));
        }
        var enabled = await users.SetTwoFactorEnabledAsync(user, true);
        if (!enabled.Succeeded) { TempData["Warning"] = "Не вдалося увімкнути 2FA."; return RedirectToAction(nameof(TwoFactor)); }
        await signIn.RefreshSignInAsync(user);
        TempData["Success"] = "Двофакторний захист увімкнено. Наступного разу потрібен код.";
        return RedirectToAction(nameof(TwoFactor));
    }

    [HttpPost("disable-2fa")]
    [EnableRateLimiting("twofactor")]
    public async Task<IActionResult> DisableTwoFactor(TwoFactorSetupVm model)
    {
        var user = await users.GetUserAsync(User);
        if (user is null) return Challenge();
        if (!await users.GetTwoFactorEnabledAsync(user)) return RedirectToAction(nameof(TwoFactor));
        var code = (model.Code ?? "").Replace(" ", "").Replace("-", "");
        if (!await users.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultAuthenticatorProvider, code))
        {
            TempData["Warning"] = "Для вимкнення 2FA введіть поточний код із застосунку.";
            return RedirectToAction(nameof(TwoFactor));
        }
        await users.SetTwoFactorEnabledAsync(user, false);
        await users.ResetAuthenticatorKeyAsync(user); // revoke previous shared key
        await signIn.RefreshSignInAsync(user);
        TempData["Success"] = "2FA вимкнено. Старий секретний ключ більше не працює.";
        return RedirectToAction(nameof(TwoFactor));
    }

    [HttpPost("link-google")]
    public IActionResult LinkGoogle()
    {
        if (string.IsNullOrWhiteSpace(config["Authentication:Google:ClientId"]) ||
            string.IsNullOrWhiteSpace(config["Authentication:Google:ClientSecret"]))
        {
            TempData["Warning"] = "Google OpenID Connect ще не налаштовано.";
            return RedirectToAction(nameof(Index));
        }
        var callback = Url.Action(nameof(LinkGoogleCallback), "Profile");
        var properties = signIn.ConfigureExternalAuthenticationProperties("Google", callback, users.GetUserId(User));
        return Challenge(properties, "Google");
    }

    [HttpGet("link-google-callback")]
    public async Task<IActionResult> LinkGoogleCallback(string? remoteError = null)
    {
        var user = await users.GetUserAsync(User);
        if (user is null) return Challenge();
        var info = await signIn.GetExternalLoginInfoAsync(user.Id);
        if (!string.IsNullOrEmpty(remoteError) || info is null || info.LoginProvider != "Google")
        {
            TempData["Warning"] = "Не вдалося прив'язати Google.";
            return RedirectToAction(nameof(Index));
        }
        var linked = await users.AddLoginAsync(user, info);
        await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);
        TempData[linked.Succeeded ? "Success" : "Warning"] = linked.Succeeded
            ? "Google успішно прив'язано. Тепер доступний вхід через Google."
            : "Цей Google-акаунт уже прив'язано або операцію не вдалося виконати.";
        return RedirectToAction(nameof(Index));
    }
}
