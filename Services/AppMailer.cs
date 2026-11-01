using System.Net;
using System.Net.Mail;
using SecureAccountsLab6.Data;
using SecureAccountsLab6.Models;

namespace SecureAccountsLab6.Services;

public interface IAppMailer
{
    Task SendActionAsync(string recipient, string subject, string category, string actionUrl, CancellationToken ct = default);
}

public sealed class AppMailer(AppDbContext db, IConfiguration config, IWebHostEnvironment environment) : IAppMailer
{
    public async Task SendActionAsync(string recipient, string subject, string category, string actionUrl, CancellationToken ct = default)
    {
        if (environment.IsDevelopment() && config["Mail:Mode"] == "Development")
        {
            db.DevMails.Add(new DevMail { Recipient = recipient, Subject = subject, Category = category, ActionUrl = actionUrl });
            await db.SaveChangesAsync(ct);
            return;
        }
        if (config["Mail:Mode"] != "Smtp") throw new InvalidOperationException("Для надсилання пошти налаштуйте SMTP.");
        var host = config["Mail:Smtp:Host"];
        var from = config["Mail:From"];
        if (string.IsNullOrWhiteSpace(host) || string.IsNullOrWhiteSpace(from))
            throw new InvalidOperationException("Відсутні SMTP Host або From.");
        using var client = new SmtpClient(host, config.GetValue("Mail:Smtp:Port", 587))
        {
            EnableSsl = config.GetValue("Mail:Smtp:EnableSsl", true),
            Credentials = new NetworkCredential(config["Mail:Smtp:Username"], config["Mail:Smtp:Password"]),
            DeliveryMethod = SmtpDeliveryMethod.Network
        };
        using var message = new MailMessage { From = new MailAddress(from), Subject = subject, IsBodyHtml = true };
        message.To.Add(new MailAddress(recipient));
        // Only server-generated links are rendered; HTML-encode all substituted values.
        message.Body = $"<div style='font-family:Arial,sans-serif'><h2>{WebUtility.HtmlEncode(subject)}</h2><p>Перейдіть за посиланням:</p><p><a href='{WebUtility.HtmlEncode(actionUrl)}'>Продовжити</a></p><p>Якщо ви цього не запитували, ігноруйте лист.</p></div>";
        await client.SendMailAsync(message, ct);
    }
}
