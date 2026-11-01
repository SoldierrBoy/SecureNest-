using System.ComponentModel.DataAnnotations;

namespace SecureAccountsLab6.ViewModels;

public sealed class RegisterVm
{
    [Required(ErrorMessage = "Вкажіть ім'я.")]
    [StringLength(60, MinimumLength = 2, ErrorMessage = "Ім'я має містити 2–60 символів.")]
    public string DisplayName { get; set; } = "";
    [Required(ErrorMessage = "Вкажіть пошту.")]
    [EmailAddress(ErrorMessage = "Некоректна електронна пошта.")]
    public string Email { get; set; } = "";
    [Required(ErrorMessage = "Вкажіть пароль.")]
    [DataType(DataType.Password)] public string Password { get; set; } = "";
    [Required(ErrorMessage = "Підтвердьте пароль.")]
    [Compare(nameof(Password), ErrorMessage = "Паролі не збігаються.")]
    [DataType(DataType.Password)] public string ConfirmPassword { get; set; } = "";
    [Required(ErrorMessage = "Пройдіть CAPTCHA.")]
    public string Captcha { get; set; } = "";
}

public sealed class LoginVm
{
    [Required(ErrorMessage = "Вкажіть пошту.")]
    [EmailAddress(ErrorMessage = "Некоректна електронна пошта.")]
    public string Email { get; set; } = "";
    [Required(ErrorMessage = "Вкажіть пароль.")]
    public string Password { get; set; } = "";
    public bool RememberMe { get; set; }
}

public sealed class Verify2FaVm
{
    [Required(ErrorMessage = "Вкажіть код.")]
    public string Code { get; set; } = "";
    public bool RememberMe { get; set; }
}

public sealed class ForgotPasswordVm
{
    [Required(ErrorMessage = "Вкажіть пошту.")]
    [EmailAddress(ErrorMessage = "Некоректна електронна пошта.")]
    public string Email { get; set; } = "";
}

public sealed class ResetPasswordVm
{
    [Required] public string UserId { get; set; } = "";
    [Required] public string Token { get; set; } = "";
    [Required(ErrorMessage = "Вкажіть новий пароль.")]
    public string Password { get; set; } = "";
    [Compare(nameof(Password), ErrorMessage = "Паролі не збігаються.")]
    public string ConfirmPassword { get; set; } = "";
}

public sealed class TwoFactorSetupVm
{
    public bool Enabled { get; set; }
    public string SharedKey { get; set; } = "";
    public string AuthenticatorUri { get; set; } = "";
    public string Code { get; set; } = "";
    public string Password { get; set; } = "";
}
