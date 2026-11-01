using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using SecureAccountsLab6.Models;
using SecureAccountsLab6.Services;
using SecureAccountsLab6.ViewModels;

namespace SecureAccountsLab6.Controllers;

[Route("auth")]
public sealed class AuthController(
    UserManager<AppUser> users, SignInManager<AppUser> signIn,
    CaptchaService captcha, IAppMailer mailer, AuditService audit, IConfiguration configuration,
    ILogger<AuthController> logger) : Controller
{
    [HttpGet("register")]
    [AllowAnonymous]
    public IActionResult Register() => User.Identity?.IsAuthenticated == true ? RedirectToAction("Index", "Profile") : View(new RegisterVm());

    [HttpPost("register")]
    [AllowAnonymous]
    [EnableRateLimiting("register")]
    public async Task<IActionResult> Register(RegisterVm model)
    {
        // Consume the challenge even if another field is invalid.
        if (!captcha.Validate(HttpContext.Session, model.Captcha))
            ModelState.AddModelError(nameof(model.Captcha), "Неправильна або прострочена CAPTCHA. Спробуйте ще раз.");
        if (!ModelState.IsValid) return View(model);

        var user = new AppUser
        {
            UserName = model.Email.Trim(), Email = model.Email.Trim(),
            DisplayName = model.DisplayName.Trim(), CreatedAtUtc = DateTime.UtcNow
        };
        var result = await users.CreateAsync(user, model.Password);
        if (!result.Succeeded)
        {
            foreach (var error in result.Errors)
                ModelState.AddModelError(error.Code is "DuplicateEmail" or "DuplicateUserName" ? nameof(model.Email) : nameof(model.Password),
                    error.Code is "DuplicateEmail" or "DuplicateUserName" ? "Ця адреса вже використовується." : error.Description);
            return View(model);
        }
        await users.AddToRoleAsync(user, "User");
        var token = await users.GenerateEmailConfirmationTokenAsync(user);
        var url = Url.Action(nameof(Activate), "Auth", new { userId = user.Id, token }, Request.Scheme)!;
        try { await mailer.SendActionAsync(user.Email!, "Підтвердження реєстрації", "ACTIVATION", url); }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed sending activation mail");
            // Account remains inactive. Re-send capability is provided from the login page.
            TempData["Warning"] = "Обліковий запис створено, але лист не вдалося надіслати. Спробуйте надіслати повторно.";
        }
        TempData["Success"] = "Акаунт створено. Підтвердьте адресу пошти, щоб увійти.";
        return RedirectToAction(nameof(Login));
    }

    [HttpGet("activate")]
    [AllowAnonymous]
    public async Task<IActionResult> Activate(string? userId, string? token)
    {
        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(token)) return View("TokenInvalid");
        var user = await users.FindByIdAsync(userId);
        if (user is null || user.EmailConfirmed) return View("TokenInvalid");
        var result = await users.ConfirmEmailAsync(user, token);
        if (!result.Succeeded) return View("TokenInvalid");
        TempData["Success"] = "Пошту підтверджено! Тепер можна увійти.";
        return RedirectToAction(nameof(Login));
    }

    [HttpPost("resend-activation")]
    [AllowAnonymous]
    [EnableRateLimiting("recover")]
    public async Task<IActionResult> ResendActivation(ForgotPasswordVm model)
    {
        if (ModelState.IsValid)
        {
            var user = await users.FindByEmailAsync(model.Email.Trim());
            if (user is { EmailConfirmed: false, IsBlocked: false })
            {
                var token = await users.GenerateEmailConfirmationTokenAsync(user);
                var url = Url.Action(nameof(Activate), "Auth", new { userId = user.Id, token }, Request.Scheme)!;
                try { await mailer.SendActionAsync(user.Email!, "Підтвердження реєстрації", "ACTIVATION", url); }
                catch (Exception ex) { logger.LogWarning(ex, "Resend activation email failed"); }
            }
        }
        TempData["Success"] = "Якщо акаунт існує та ще не активований, повідомлення надіслано.";
        return RedirectToAction(nameof(Login));
    }

    [HttpGet("login")]
    [AllowAnonymous]
    public IActionResult Login(string? returnUrl = null, bool googleError = false)
    {
        if (googleError) TempData["Warning"] = "Google-вхід скасовано або сталася помилка провайдера.";
        ViewBag.ReturnUrl = IsSafeReturnUrl(returnUrl) ? returnUrl : null;
        return View(new LoginVm());
    }

    [HttpPost("login")]
    [AllowAnonymous]
    [EnableRateLimiting("login")]
    public async Task<IActionResult> Login(LoginVm model, string? returnUrl = null)
    {
        ViewBag.ReturnUrl = IsSafeReturnUrl(returnUrl) ? returnUrl : null;
        if (!ModelState.IsValid) return View(model);
        var email = model.Email.Trim();
        var user = await users.FindByEmailAsync(email);
        if (user is null)
        {
            await audit.LogAsync(email, "FAILED_PASSWORD");
            ModelState.AddModelError("", "Некоректні дані для входу.");
            return View(model);
        }
        if (user.IsBlocked)
        {
            await audit.LogAsync(email, "ADMIN_BLOCKED", user);
            ModelState.AddModelError("", "Акаунт заблоковано адміністратором.");
            return View(model);
        }
        var result = await signIn.PasswordSignInAsync(user, model.Password, model.RememberMe, lockoutOnFailure: true);
        if (result.IsLockedOut)
        {
            await audit.LogAsync(email, "LOCKED_OUT", user);
            ModelState.AddModelError("", "Забагато помилкових спроб. Повторіть вхід приблизно за 15 хвилин.");
            return View(model);
        }
        if (result.RequiresTwoFactor)
        {
            await audit.LogAsync(email, "2FA_REQUIRED", user);
            return RedirectToAction(nameof(Verify2Fa), new { returnUrl = ViewBag.ReturnUrl, rememberMe = model.RememberMe });
        }
        if (!result.Succeeded)
        {
            await audit.LogAsync(email, result.IsNotAllowed ? "EMAIL_NOT_CONFIRMED" : "FAILED_PASSWORD", user);
            ModelState.AddModelError("", result.IsNotAllowed ? "Потрібно підтвердити email перед входом." : "Некоректні дані для входу.");
            return View(model);
        }
        user.LastLoginUtc = DateTime.UtcNow;
        await users.UpdateAsync(user);
        await audit.LogAsync(email, "SUCCESS", user);
        return SafeRedirect(returnUrl);
    }

    [HttpGet("verify-2fa")]
    [AllowAnonymous]
    public async Task<IActionResult> Verify2Fa(bool rememberMe = false, string? returnUrl = null)
    {
        if (await signIn.GetTwoFactorAuthenticationUserAsync() is null) return RedirectToAction(nameof(Login));
        ViewBag.ReturnUrl = IsSafeReturnUrl(returnUrl) ? returnUrl : null;
        return View(new Verify2FaVm { RememberMe = rememberMe });
    }

    [HttpPost("verify-2fa")]
    [AllowAnonymous]
    [EnableRateLimiting("twofactor")]
    public async Task<IActionResult> Verify2Fa(Verify2FaVm model, string? returnUrl = null)
    {
        ViewBag.ReturnUrl = IsSafeReturnUrl(returnUrl) ? returnUrl : null;
        var user = await signIn.GetTwoFactorAuthenticationUserAsync();
        if (user is null) return RedirectToAction(nameof(Login));
        if (user.IsBlocked)
        {
            await signIn.SignOutAsync();
            await audit.LogAsync(user.Email, "ADMIN_BLOCKED", user);
            return RedirectToAction(nameof(Login));
        }
        if (!ModelState.IsValid) return View(model);
        var code = model.Code.Replace(" ", "").Replace("-", "");
        var result = await signIn.TwoFactorAuthenticatorSignInAsync(code, model.RememberMe, rememberClient: false);
        if (result.Succeeded)
        {
            user.LastLoginUtc = DateTime.UtcNow;
            await users.UpdateAsync(user);
            await audit.LogAsync(user.Email, "SUCCESS_2FA", user);
            return SafeRedirect(returnUrl);
        }
        await audit.LogAsync(user.Email, result.IsLockedOut ? "LOCKED_OUT_2FA" : "FAILED_2FA", user);
        ModelState.AddModelError("", result.IsLockedOut ? "Акаунт тимчасово заблоковано через помилкові коди." : "Неправильний код автентифікатора.");
        return View(model);
    }

    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        await signIn.SignOutAsync();
        TempData["Success"] = "Ви вийшли з облікового запису.";
        return RedirectToAction("Index", "Home");
    }

    [HttpGet("forgot-password")]
    [AllowAnonymous]
    public IActionResult ForgotPassword() => View(new ForgotPasswordVm());

    [HttpPost("forgot-password")]
    [AllowAnonymous]
    [EnableRateLimiting("recover")]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordVm model)
    {
        if (!ModelState.IsValid) return View(model);
        var user = await users.FindByEmailAsync(model.Email.Trim());
        if (user is { EmailConfirmed: true, IsBlocked: false })
        {
            var token = await users.GeneratePasswordResetTokenAsync(user);
            var url = Url.Action(nameof(ResetPassword), "Auth", new { userId = user.Id, token }, Request.Scheme)!;
            try { await mailer.SendActionAsync(user.Email!, "Відновлення пароля", "RESET", url); }
            catch (Exception ex) { logger.LogWarning(ex, "Password reset email delivery failed"); }
        }
        return View("ForgotSent"); // anti-enumeration: always same result
    }

    [HttpGet("reset-password")]
    [AllowAnonymous]
    public IActionResult ResetPassword(string? userId, string? token)
    {
        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(token)) return View("TokenInvalid");
        return View(new ResetPasswordVm { UserId = userId, Token = token });
    }

    [HttpPost("reset-password")]
    [AllowAnonymous]
    [EnableRateLimiting("recover")]
    public async Task<IActionResult> ResetPassword(ResetPasswordVm model)
    {
        if (!ModelState.IsValid) return View(model);
        var user = await users.FindByIdAsync(model.UserId);
        if (user is null || user.IsBlocked) return View("TokenInvalid");
        var result = await users.ResetPasswordAsync(user, model.Token, model.Password);
        if (!result.Succeeded)
        {
            foreach (var error in result.Errors)
                ModelState.AddModelError("", error.Code == "InvalidToken" ? "Токен недійсний або прострочений." : error.Description);
            return View(model);
        }
        await audit.LogAsync(user.Email, "PASSWORD_RESET", user);
        TempData["Success"] = "Пароль змінено. Увійдіть із новим паролем.";
        return RedirectToAction(nameof(Login));
    }

    [HttpGet("google")]
    [AllowAnonymous]
    public IActionResult Google(string? returnUrl = null)
    {
        if (!GoogleConfigured()) return RedirectToAction(nameof(Login));
        var callback = Url.Action(nameof(GoogleCallback), "Auth", new { returnUrl = IsSafeReturnUrl(returnUrl) ? returnUrl : null });
        var properties = signIn.ConfigureExternalAuthenticationProperties("Google", callback);
        return Challenge(properties, "Google");
    }

    [HttpGet("google-callback")]
    [AllowAnonymous]
    public async Task<IActionResult> GoogleCallback(string? returnUrl = null, string? remoteError = null)
    {
        if (!string.IsNullOrWhiteSpace(remoteError))
        {
            TempData["Warning"] = "Google не підтвердив авторизацію.";
            return RedirectToAction(nameof(Login));
        }
        var info = await signIn.GetExternalLoginInfoAsync();
        if (info is null || info.LoginProvider != "Google") return RedirectToAction(nameof(Login));
        var email = info.Principal.FindFirstValue(ClaimTypes.Email) ?? info.Principal.FindFirstValue("email");
        var emailVerified = info.Principal.FindFirst("email_verified")?.Value;
        if (string.IsNullOrWhiteSpace(email) || !string.Equals(emailVerified, "true", StringComparison.OrdinalIgnoreCase))
        {
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);
            TempData["Warning"] = "Google має підтвердити email для входу.";
            return RedirectToAction(nameof(Login));
        }
        var user = await users.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
        if (user is null)
        {
            // Never auto-merge a Google login with an existing password account by email alone.
            if (await users.FindByEmailAsync(email) is not null)
            {
                await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);
                TempData["Warning"] = "Цей email уже зареєстровано. Увійдіть паролем і прив'яжіть Google у профілі.";
                return RedirectToAction(nameof(Login));
            }
            user = new AppUser
            {
                UserName = email, Email = email, EmailConfirmed = true,
                DisplayName = info.Principal.FindFirstValue(ClaimTypes.Name) ?? email.Split('@')[0],
                CreatedAtUtc = DateTime.UtcNow
            };
            var created = await users.CreateAsync(user);
            if (!created.Succeeded) return RedirectToAction(nameof(Login));
            await users.AddToRoleAsync(user, "User");
            var linked = await users.AddLoginAsync(user, info);
            if (!linked.Succeeded) return RedirectToAction(nameof(Login));
        }
        if (user.IsBlocked || !user.EmailConfirmed)
        {
            await audit.LogAsync(email, "ADMIN_BLOCKED", user);
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);
            TempData["Warning"] = "Доступ до акаунта обмежено.";
            return RedirectToAction(nameof(Login));
        }
        // This method uses Identity's existing 2FA checks for linked Google accounts.
        var result = await signIn.ExternalLoginSignInAsync("Google", info.ProviderKey, isPersistent: false, bypassTwoFactor: false);
        if (result.RequiresTwoFactor)
        {
            await audit.LogAsync(email, "2FA_REQUIRED", user);
            return RedirectToAction(nameof(Verify2Fa), new { returnUrl });
        }
        if (!result.Succeeded) return RedirectToAction(nameof(Login));
        user.LastLoginUtc = DateTime.UtcNow;
        await users.UpdateAsync(user);
        await audit.LogAsync(email, "SUCCESS_GOOGLE", user);
        await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);
        return SafeRedirect(returnUrl);
    }

    [HttpGet("access-denied")]
    public IActionResult AccessDenied() => View();

    private bool GoogleConfigured() => !string.IsNullOrWhiteSpace(configuration["Authentication:Google:ClientId"]) &&
        !string.IsNullOrWhiteSpace(configuration["Authentication:Google:ClientSecret"]);
    private bool IsSafeReturnUrl(string? url) => !string.IsNullOrWhiteSpace(url) && Url.IsLocalUrl(url);
    private IActionResult SafeRedirect(string? url) => IsSafeReturnUrl(url) ? LocalRedirect(url!) : RedirectToAction("Index", "Profile")!;
}
