using Microsoft.AspNetCore.Mvc;

namespace SecureAccountsLab6.Controllers;

public sealed class HomeController : Controller
{
    public IActionResult Index() => View();
    [Route("home/error")]
    public IActionResult Error() => View();
}
