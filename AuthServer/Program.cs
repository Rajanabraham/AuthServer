using AuthServer;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddRazorPages();
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    // Configure Entity Framework Core to use Microsoft SQL Server.
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));

    // Register the entity sets needed by OpenIddict.
    // Note: use the generic overload if you need to replace the default OpenIddict entities.
    options.UseOpenIddict();
});

// Configure Identity
builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();


builder.Services.AddOpenIddict()

    // Register the OpenIddict core components.
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
               .UseDbContext<ApplicationDbContext>();
    });

builder.Services.AddOpenIddict()

    // Register the OpenIddict server components.
    .AddServer(options =>
    {
       // options.DisableAccessTokenEncryption();
        // Enable the token endpoint.
        options.SetAuthorizationEndpointUris("connect/authorize")
        .SetTokenEndpointUris("connect/token")
        ;

        // Enable the Authorization credentials flow.
        options.AllowAuthorizationCodeFlow().AllowRefreshTokenFlow();

        options.RegisterScopes(
          OpenIddictConstants.Scopes.OpenId,
          OpenIddictConstants.Scopes.Email,
          OpenIddictConstants.Scopes.Profile,
          OpenIddictConstants.Scopes.OfflineAccess
      );
        // Register the signing and encryption credentials.
        //  options.AddDevelopmentEncryptionCertificate();
         options.AddDevelopmentSigningCertificate();
        //options.AddEphemeralSigningKey(); // Temporary signing key
        //options.AddEphemeralEncryptionKey(); // Temporary encryption key
        options.AddEncryptionKey(new SymmetricSecurityKey(
            Convert.FromBase64String("DRjd/GnduI3Efzen9V9BvbNUfc/VKgXltV7Kbk9sMkY=")));


        // Register the ASP.NET Core host and configure the ASP.NET Core options.
        options.UseAspNetCore()
                .EnableAuthorizationEndpointPassthrough()
               .EnableTokenEndpointPassthrough();
    });
builder.Services.AddTransient<AuthService>();
builder.Services.AddTransient<Seeder>();

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(
    c =>
    {
        c.LoginPath = "/Authenticate";
    });
// CORS
builder.Services.AddCors(options => options.AddDefaultPolicy(policy =>
    policy.WithOrigins("https://localhost:4200")
          .AllowAnyHeader()
          .AllowAnyMethod()
          .AllowCredentials()));


var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var seeder = scope.ServiceProvider.GetRequiredService<Seeder>();
    seeder.AddClients().GetAwaiter().GetResult();
}

    app.UseDeveloperExceptionPage();

app.UseForwardedHeaders();

app.UseRouting();
app.UseCors();

app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.MapRazorPages();

app.Run();
