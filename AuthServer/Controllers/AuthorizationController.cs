using System.Security.Claims;
using AuthServer.Const;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthServer.Controllers
{
    [ApiController]
    public class AuthorizationController : Controller
    {
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly IOpenIddictAuthorizationManager _authorizationManager;
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        public readonly AuthService _authService;

        public AuthorizationController(
            IOpenIddictApplicationManager applicationManager,
            IOpenIddictAuthorizationManager authorizationManager,
            IOpenIddictScopeManager scopeManager,
            SignInManager<IdentityUser> signInManager,
            UserManager<IdentityUser> userManager,
            AuthService authService)
        {
            _applicationManager = applicationManager;
            _authorizationManager = authorizationManager;
            _scopeManager = scopeManager;
            _signInManager = signInManager;
            _userManager = userManager;
            _authService = authService;
        }

        [HttpGet("~/connect/authorize")]
        [HttpPost("~/connect/authorize")]
        public async Task<IActionResult> Authorize()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            var isAuthenticated = _authService.IsAuthenticated(result, request);
            var parameters = _authService.ParseOAuthParameters(HttpContext);
            if (!isAuthenticated)
            {
                return Challenge(
                    authenticationSchemes: CookieAuthenticationDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties
                    {
                        RedirectUri = _authService.BuilderRedirectUrl(HttpContext.Request, parameters)
                    });
            }

            var user = await _userManager.GetUserAsync(result.Principal) ??
                throw new InvalidOperationException("The user details cannot be retrieved.");

            var application = await _applicationManager.FindByClientIdAsync(request.ClientId) ??
                throw new InvalidOperationException("Details concerning the calling client application cannot be found.");

            var identity = new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            identity.SetClaim(Claims.Subject, user.Id)
                .SetClaim(Claims.Email, user.Email)
                .SetClaim(Claims.Name, user.UserName);
            identity.SetScopes(request.GetScopes());
            identity.SetResources(await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());

            var authorizations = await _authorizationManager.FindAsync(
                subject: user.Id,
                client: await _applicationManager.GetIdAsync(application),
                status: Statuses.Valid,
                type: AuthorizationTypes.Permanent,
                scopes: request.GetScopes())
                .ToListAsync();
            var authorization = authorizations.LastOrDefault();
            authorization ??= await _authorizationManager.CreateAsync(
                identity: identity,
                subject: user.Id,
                client: await _applicationManager.GetIdAsync(application),
                type: AuthorizationTypes.Permanent,
                scopes: identity.GetScopes()
            );

            identity.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
            identity.SetDestinations(AuthService.GetDestinations);
            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        [HttpPost("~/connect/token")]
        public async Task<IActionResult> Exchange()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            try
            {
                if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
                {
                    return await HandleCodeOrRefreshTokenGrant(request);
                }

                if (request.GrantType == ExtensionGrant.PasswordlessExtensionGrantName)
                {
                    return await HandlePasswordlessGrant(request);
                }

                return BadRequest(new AuthenticationProperties(new Dictionary<string, string>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.UnsupportedGrantType,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The specified grant type is not supported."
                }));
            }
            catch (Exception)
            {
                return CreateForbidResult(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    Errors.InvalidGrant,
                    "An error occurred while processing the token.");
            }
        }

        [HttpGet("~/connect/logout")]
        public async Task<IActionResult> LogoutPost()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return SignOut(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties { RedirectUri = "/" });
        }

        private async Task<IActionResult> HandleCodeOrRefreshTokenGrant(OpenIddictRequest request)
        {
            var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            if (result?.Principal == null)
                return InvalidToken();

            var subject = result.Principal.GetClaim(Claims.Subject);
            if (string.IsNullOrEmpty(subject))
                return InvalidTokenSubject();

            var user = await _userManager.FindByIdAsync(subject);
            if (user == null)
                return TokenNoLongerValid();

            if (!await _signInManager.CanSignInAsync(user))
                return UserCannotSignIn();

            var identity = CreateIdentity(result.Principal.Claims, user);
            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        private async Task<IActionResult> HandlePasswordlessGrant(OpenIddictRequest request)
        {
            var phoneNumber = request.GetParameter("phone_number")?.ToString()?.Trim();
            if (string.IsNullOrEmpty(phoneNumber))
                return BadRequest(new Dictionary<string, string>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant
                });

            var user = await _userManager.Users.FirstOrDefaultAsync(u => u.PhoneNumber == phoneNumber);
            if (user == null)
                return InvalidGrant();

            if (!await _signInManager.CanSignInAsync(user))
                return UserCannotSignIn();

            var principal = await _signInManager.CreateUserPrincipalAsync(user);
            var roles = await _userManager.GetRolesAsync(user);

            var identity = CreateIdentity(principal.Claims, user);
            identity.AddClaim(new Claim("role", string.Join(",", roles)));
            identity.SetScopes(request.GetScopes());
            identity.SetResources(await _scopeManager.ListResourcesAsync(request.GetScopes()).ToListAsync());

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        private ClaimsIdentity CreateIdentity(IEnumerable<Claim> existingClaims, IdentityUser user)
        {
            var identity = new ClaimsIdentity(
                existingClaims,
                TokenValidationParameters.DefaultAuthenticationType,
                Claims.Name,
                Claims.Role);

            identity.SetClaim(Claims.Subject, user.Id)
                    .SetClaim(Claims.Email, user.Email)
                    .SetClaim(Claims.Name, user.UserName)
                    .SetClaim(Claims.PreferredUsername, user.UserName)
                    .SetDestinations(AuthService.GetDestinations);

            return identity;
        }

        // Helper methods for common error responses
        private IActionResult InvalidToken() =>
            CreateForbidResult(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                Errors.InvalidGrant, "Invalid token.");

        private IActionResult InvalidTokenSubject() =>
            CreateForbidResult(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                Errors.InvalidGrant, "Invalid token subject.");

        private IActionResult TokenNoLongerValid() =>
            CreateForbidResult(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                Errors.InvalidGrant, "The token is no longer valid.");

        private IActionResult UserCannotSignIn() =>
            CreateForbidResult(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                Errors.InvalidGrant, "The user is no longer allowed to sign in.");

        private IActionResult InvalidGrant() =>
            CreateForbidResult(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                Errors.InvalidGrant);

        private IActionResult CreateForbidResult(string authenticationScheme, string error, string description = null)
        {
            var properties = new AuthenticationProperties();
            properties.SetParameter(OpenIddictServerAspNetCoreConstants.Properties.Error, error);

            if (!string.IsNullOrEmpty(description))
                properties.SetParameter(OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription, description);

            return Forbid(properties, authenticationScheme);
        }
    }
}