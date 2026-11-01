using System.Security.Cryptography;
using System.Text;
using System.Net;

namespace SecureAccountsLab6.Services;

public sealed class CaptchaService
{
    private const string Alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    private const string AnswerKey = "captcha.hash";
    private const string ExpiresKey = "captcha.expires";

    public string GenerateSvg(ISession session)
    {
        var code = new string(Enumerable.Range(0, 6).Select(_ => Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)]).ToArray());
        session.SetString(AnswerKey, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(code))));
        session.SetString(ExpiresKey, DateTimeOffset.UtcNow.AddMinutes(4).ToUnixTimeSeconds().ToString());
        var result = new StringBuilder();
        result.Append("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 290 88\" role=\"img\" aria-label=\"CAPTCHA challenge\">");
        result.Append("<rect width=\"290\" height=\"88\" rx=\"15\" fill=\"#101d33\"/>");
        for (int i = 0; i < 18; i++)
        {
            int x1 = RandomNumberGenerator.GetInt32(290), y1 = RandomNumberGenerator.GetInt32(88);
            int x2 = RandomNumberGenerator.GetInt32(290), y2 = RandomNumberGenerator.GetInt32(88);
            result.Append($"<path d=\"M{x1} {y1}L{x2} {y2}\" stroke=\"#44617b\" stroke-width=\"1\" opacity=\".6\"/>");
        }
        for (int i = 0; i < code.Length; i++)
        {
            var x = 28 + i * 43 + RandomNumberGenerator.GetInt32(-3, 4);
            var y = 57 + RandomNumberGenerator.GetInt32(-8, 8);
            var angle = RandomNumberGenerator.GetInt32(-17, 18);
            var fill = i % 2 == 0 ? "#d9fff7" : "#8ce9d5";
            result.Append($"<text x=\"{x}\" y=\"{y}\" font-family=\"Arial,sans-serif\" font-size=\"39\" font-weight=\"bold\" fill=\"{fill}\" transform=\"rotate({angle} {x} {y})\">{WebUtility.HtmlEncode(code[i].ToString())}</text>");
        }
        result.Append("</svg>");
        return result.ToString();
    }

    public bool Validate(ISession session, string? response)
    {
        var storedHash = session.GetString(AnswerKey);
        var expires = session.GetString(ExpiresKey);
        session.Remove(AnswerKey); // one attempt, irrespective of outcome
        session.Remove(ExpiresKey);
        if (storedHash is null || !long.TryParse(expires, out var until) ||
            until < DateTimeOffset.UtcNow.ToUnixTimeSeconds() || string.IsNullOrWhiteSpace(response)) return false;
        var candidate = response.Trim().ToUpperInvariant();
        var actual = SHA256.HashData(Encoding.UTF8.GetBytes(candidate));
        try { return CryptographicOperations.FixedTimeEquals(Convert.FromHexString(storedHash), actual); }
        catch (FormatException) { return false; }
    }
}
