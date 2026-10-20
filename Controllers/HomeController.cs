using System.Diagnostics;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Models;

namespace SafeVault.Controllers;

public class HomeController : Controller
{
    public IActionResult Index()
    {
        return View(new User());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult Submit([Bind(nameof(SafeVault.Models.User.Username), nameof(SafeVault.Models.User.Email))] User model)
    {
        model.Sanitize(HtmlEncoder.Default);

        if (!ModelState.IsValid)
        {
            return View("Index", model);
        }

        ViewBag.Message = "Submitted successfully.";
        return View("Index", new User());
    }

    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}
