using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Validation.AspNetCore;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

//// Add JWT Bearer Authentication
//builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
//    .AddJwtBearer(options =>
//    {
//        options.Authority = "https://localhost:44355"; // Your auth server
//        options.Audience = "https://localhost:44347";   // Service1 resource URI
//        options.TokenValidationParameters = new TokenValidationParameters
//        {
//            ValidateIssuer = true,
//            ValidateAudience = true,
//            ValidateLifetime = true,
//            ValidateIssuerSigningKey = true,
//        };
//    });

// Configure authentication with a default scheme
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
});

// Add OpenIddict validation separately
builder.Services.AddOpenIddict()
    .AddValidation(options =>
    {
        // Set the issuer (your OpenIddict server)
        options.SetIssuer("https://localhost:44355/");

        // Add the encryption key. Local use.
        options.AddEncryptionKey(new SymmetricSecurityKey(
             Convert.FromBase64String("DRjd/GnduI3Efzen9V9BvbNUfc/VKgXltV7Kbk9sMkY=")));

        // Register the System.Net.Http integration for server discovery
        options.UseSystemNetHttp();

        // Use ASP.NET Core integration
        options.UseAspNetCore();
    });


// Add authorization policy for the service1 scope
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("Service1Policy", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireClaim("scope", "service2"); // Require the service1 scope
    });
});
// CORS
builder.Services.AddCors(options => options.AddDefaultPolicy(policy =>
    policy.WithOrigins("https://localhost:4200")
          .AllowAnyHeader()
          .AllowAnyMethod()
          .AllowCredentials()));


var app = builder.Build();

app.UseRouting();
app.UseCors();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();