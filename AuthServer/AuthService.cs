using Azure.Core;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Primitives;
using OpenIddict.Abstractions;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthServer
{
    public class AuthService
    {
        public bool IsAuthenticated(AuthenticateResult authenticateResult,OpenIddictRequest request)
        {
            if(!authenticateResult.Succeeded)
            {
                return false;
            }
            if(request.MaxAge.HasValue && authenticateResult.Properties != null)
            {
                var maxAgeSeconds = TimeSpan.FromSeconds(request.MaxAge.Value);
                var expired = !authenticateResult.Properties.IssuedUtc.HasValue ||
                    DateTimeOffset.UtcNow - authenticateResult.Properties.IssuedUtc > maxAgeSeconds;
                if(expired)
                {
                    return false;
                }
            }
            return true;
        }

        public IDictionary<string, StringValues> ParseOAuthParameters(HttpContext httpcontext, List<string> excluding = null)
        {
            var parameters = httpcontext.Request.HasFormContentType
                ? httpcontext.Request.Form
                    .Where(parameter => excluding == null || !excluding.Contains(parameter.Key))
                    .ToDictionary(kvp => kvp.Key, kvp => kvp.Value)
                : httpcontext.Request.Query
                    .Where(parameter => excluding == null || !excluding.Contains(parameter.Key))
                    .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
            return parameters;
        }

        public string BuilderRedirectUrl(HttpRequest request, IDictionary<string,StringValues> parameters)
        {
            var url = request.PathBase + request.Path + QueryString.Create(parameters);
            return url;
        }

        public static List<string> GetDestinations(Claim claim)
        {
            var destinations = new List<string>();
            if(claim.Type is OpenIddictConstants.Claims.Name or OpenIddictConstants.Claims.Email)
            {
                destinations.Add(OpenIddictConstants.Destinations.AccessToken);
            }
            return destinations;
        }
    }
}
