using AuthServer;
using AuthServer.Const;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;

var builder = WebApplication.CreateBuilder(args);

// Register ApplicationDbContext
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")); // Or UseSqlServer, etc.
    options.UseOpenIddict();
});

builder.Services.AddControllers();
builder.Services.AddRazorPages();
// Configure Identity
builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
               .UseDbContext<ApplicationDbContext>();
    })
    // Register the OpenIddict server components.
    .AddServer(options =>
    {
       // options.DisableAccessTokenEncryption();
        // Enable the token endpoint.
        options.SetAuthorizationEndpointUris("connect/authorize")
        .SetTokenEndpointUris("connect/token")
        ;

        // Enable the Authorization credentials flow.
        options.AllowAuthorizationCodeFlow().AllowRefreshTokenFlow().AllowCustomFlow(ExtensionGrant.PasswordlessExtensionGrantName);

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
app.UseDeveloperExceptionPage();
app.UseForwardedHeaders();
app.UseRouting();
app.UseCors();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.MapRazorPages();
app.Run();
