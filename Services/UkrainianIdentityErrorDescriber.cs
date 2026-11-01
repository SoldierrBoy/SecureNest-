using Microsoft.AspNetCore.Identity;

namespace SecureAccountsLab6.Services;

public sealed class UkrainianIdentityErrorDescriber : IdentityErrorDescriber
{
    public override IdentityError PasswordTooShort(int length) => new()
    {
        Code = nameof(PasswordTooShort), Description = $"Пароль має містити щонайменше {length} символів."
    };
    public override IdentityError PasswordRequiresNonAlphanumeric() => new()
    {
        Code = nameof(PasswordRequiresNonAlphanumeric), Description = "Додайте спеціальний символ (наприклад, ! або #)."
    };
    public override IdentityError PasswordRequiresDigit() => new()
    {
        Code = nameof(PasswordRequiresDigit), Description = "Пароль має містити хоча б одну цифру."
    };
    public override IdentityError PasswordRequiresLower() => new()
    {
        Code = nameof(PasswordRequiresLower), Description = "Пароль має містити малу латинську літеру."
    };
    public override IdentityError PasswordRequiresUpper() => new()
    {
        Code = nameof(PasswordRequiresUpper), Description = "Пароль має містити велику латинську літеру."
    };
    public override IdentityError PasswordRequiresUniqueChars(int uniqueChars) => new()
    {
        Code = nameof(PasswordRequiresUniqueChars), Description = $"Пароль має містити мінімум {uniqueChars} різних символи."
    };
    public override IdentityError DuplicateEmail(string email) => new()
    {
        Code = nameof(DuplicateEmail), Description = "Ця електронна адреса вже зареєстрована."
    };
    public override IdentityError DuplicateUserName(string userName) => new()
    {
        Code = nameof(DuplicateUserName), Description = "Ця електронна адреса вже зареєстрована."
    };
    public override IdentityError InvalidEmail(string? email) => new()
    {
        Code = nameof(InvalidEmail), Description = "Неправильний формат електронної пошти."
    };
    public override IdentityError InvalidToken() => new()
    {
        Code = nameof(InvalidToken), Description = "Токен недійсний або його термін дії закінчився."
    };
}
