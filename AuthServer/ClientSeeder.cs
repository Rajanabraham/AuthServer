using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;

namespace AuthServer
{
    public class ClientSeeder
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly IOpenIddictScopeManager _scopeManager;
        public ClientSeeder(IServiceProvider serviceProvider, IOpenIddictScopeManager scopeManager)
        {
            _serviceProvider = serviceProvider;
            _scopeManager = scopeManager;
        }

        public async Task AddClients()
        {
            await using var scope = _serviceProvider.CreateAsyncScope();
            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            await context.Database.EnsureCreatedAsync();


            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
            if (!await userManager.Users.AnyAsync())
            {
                await userManager.CreateAsync(new IdentityUser
                {
                    UserName = "admin@example.com",
                    Email = "admin@example.com",
                    EmailConfirmed = true
                }, "Password123!");
            }

            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            var client = await manager.FindByClientIdAsync("angular-client");

            if(client != null)
            {
                await manager.DeleteAsync(client);
            }
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "angular-client",
                ClientType = OpenIddictConstants.ClientTypes.Public,
                RedirectUris = { new Uri("https://localhost:4200/callback") },
                PostLogoutRedirectUris = { new Uri("https://localhost:4200") },
                Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.ResponseTypes.Code,
                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Scopes.Roles,
                "scp:service1",
                "scp:service2"
            }
            });

            // Check if the "service1" scope already exists
            var service1 = await _scopeManager.FindByNameAsync("service1");
            if (service1 == null)
            {
                await _scopeManager.CreateAsync(new OpenIddictScopeDescriptor
                {
                    Name = "service1",
                    DisplayName = "Service1 API Access",
                    Description = "Access to Service1 API",
                    Resources = { "https://localhost:44373" } // The URI of Service1
                });
            }
            var service2 = await _scopeManager.FindByNameAsync("service2");
            if (service2 == null)
            {
                await _scopeManager.CreateAsync(new OpenIddictScopeDescriptor
                {
                    Name = "service2",
                    DisplayName = "Service1 API Access",
                    Description = "Access to Service1 API",
                    Resources = { "https://localhost:44347" } // The URI of Service2
                });
            }
        }
       
    }
}
