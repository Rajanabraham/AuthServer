using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Claims;

namespace AuthServer.Pages
{
    public class AuthenticateModel : PageModel
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;

        public AuthenticateModel(
            UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        [BindProperty]  // Add this attribute
        public string Email { get; set; }

        [BindProperty]  // Add this attribute
        public string Password { get; set; }

        [BindProperty]
        public string ReturnUrl { get; set; }

        public string AuthStatus { get; set; } = "";

        public IActionResult OnGet(string returnUrl)
        {
            ReturnUrl = returnUrl;
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (string.IsNullOrEmpty(Email))
            {
                AuthStatus = "Email is required";
                return Page();
            }

            // Find user by email
            var user = await _userManager.FindByEmailAsync(Email);

            // Validate user exists and password is correct
            if (user == null || !await _userManager.CheckPasswordAsync(user, Password))
            {
                AuthStatus = "Invalid email or password";
                return Page();
            }

            // Rest of your authentication logic...
            // Get user roles
            var roles = await _userManager.GetRolesAsync(user);

            // Create claims
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Name, user.UserName)
            };

            // Add role claims
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            // Create principal
            var claimsIdentity = new ClaimsIdentity(
                claims, CookieAuthenticationDefaults.AuthenticationScheme);

            var authProperties = new AuthenticationProperties
            {
                IsPersistent = true // For "Remember me" functionality
            };

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity),
                authProperties);

            if (!string.IsNullOrEmpty(ReturnUrl) && Url.IsLocalUrl(ReturnUrl))
            {
                return Redirect(ReturnUrl);
            }

            return RedirectToPage("/Index"); // Redirect to a success page
        }
    }
}