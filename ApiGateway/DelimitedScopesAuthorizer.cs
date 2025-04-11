using Ocelot.Authorization;
using Ocelot.Infrastructure.Claims.Parser;
using Ocelot.Responses;
using System.Security.Claims;

namespace MyGateway.Custom.Claims
{
    public class DelimitedScopesAuthorizer : IScopesAuthorizer
    {
        private readonly IClaimsParser _claimsParser;
        private readonly string _scope = "scope";
        private readonly string _msScope = "http://schemas.microsoft.com/identity/claims/scope";

        public DelimitedScopesAuthorizer(IClaimsParser claimsParser)
        {
            _claimsParser = claimsParser;
        }

        public Response<bool> Authorize(ClaimsPrincipal claimsPrincipal, List<string> routeAllowedScopes)
        {
            if (routeAllowedScopes == null || routeAllowedScopes.Count == 0)
            {
                return new OkResponse<bool>(true);
            }

            var values = _claimsParser.GetValuesByClaimType(claimsPrincipal.Claims, _msScope);
            if (!values.IsError && !values.Data.Any())
            {
                values = _claimsParser.GetValuesByClaimType(claimsPrincipal.Claims, _scope);
            }

            if (values.IsError)
            {
                return new ErrorResponse<bool>(values.Errors);
            }

            List<string> userScopes = new List<string>();
            foreach (var item in values.Data)
            {
                if (item.Contains(' '))
                {
                    var scopes = item.Split(' ').ToList();
                    userScopes.AddRange(scopes);
                }
                else
                {
                    userScopes.Add(item);
                }
            }

            var matchesScopes = routeAllowedScopes.Intersect(userScopes).ToList();

            if (matchesScopes.Count == 0)
            {
                return new OkResponse<bool>(false); 
            }
            return new OkResponse<bool>(true);
        }
    }
}