using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Ocelot.DependencyInjection;
using Ocelot.Middleware;
using Ocelot.Cache.CacheManager;
using OpenIddict.Validation.AspNetCore;
using Microsoft.Extensions.Logging;
using Serilog;
using MyGateway.Custom.Claims;
using Ocelot.Values;
using Ocelot.Authorization;
using Microsoft.Extensions.DependencyInjection.Extensions;

var builder = WebApplication.CreateBuilder(args);

//// Authentication
//builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
//    .AddJwtBearer("Bearer", options =>
//    {
//        options.Authority = "https://localhost:44355"; // Must match OpenIddict server URL
//        options.RequireHttpsMetadata = true; // Enforce HTTPS in production
//        options.TokenValidationParameters = new TokenValidationParameters
//        {
//            ValidateIssuer = true,
//            ValidIssuer = "https://localhost:44355", // Must match OpenIddict issuer
//            ValidateAudience = false, // Set to true and specify audience if required
//            ValidateLifetime = true,
//            ValidateIssuerSigningKey = true,
//            // If tokens are encrypted, add:
//             TokenDecryptionKey = new SymmetricSecurityKey(Convert.FromBase64String("DRjd/GnduI3Efzen9V9BvbNUfc/VKgXltV7Kbk9sMkY="))
//        };

//        // Development only - remove in production
//        options.BackchannelHttpHandler = new HttpClientHandler
//        {
//            ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true
//        };
//    });


// Configuration
builder.Configuration.AddJsonFile("ocelot.json", optional: false, reloadOnChange: true);

// Configure Serilog to log to a file
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Debug() // Set minimum log level to Debug
    .WriteTo.File("logs/gateway.log",
        rollingInterval: RollingInterval.Day,
        outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss} [{Level:u3}] {Message:lj}{NewLine}{Exception}")
    .CreateLogger();

builder.Host.UseSerilog(); // Integrate Serilog with the host


// Authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
});

// Add OpenIddict validation
builder.Services.AddOpenIddict()
    .AddValidation(options =>
    {
        options.SetIssuer("https://localhost:44355/");
        options.AddEncryptionKey(new SymmetricSecurityKey(
            Convert.FromBase64String("DRjd/GnduI3Efzen9V9BvbNUfc/VKgXltV7Kbk9sMkY=")));
        options.UseSystemNetHttp();
        options.UseAspNetCore();
    });

builder.Services.AddSingleton<IScopesAuthorizer, DelimitedScopesAuthorizer>();


// Ocelot with caching
builder.Services.AddOcelot(builder.Configuration)
    .AddCacheManager(x => x.WithDictionaryHandle());

// CORS
builder.Services.AddCors(options => options.AddDefaultPolicy(policy =>
    policy.WithOrigins("https://localhost:4200")
          .AllowAnyHeader()
          .AllowAnyMethod()
          .AllowCredentials()));

var app = builder.Build();

// Middleware pipeline
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage(); // Show detailed errors
}

app.UseHttpsRedirection();
app.UseRouting();
app.UseCors();
app.UseAuthentication();
app.UseAuthorization();

// Optional: Add a fallback route
app.MapGet("/", () => "Gateway is running");

await app.UseOcelot();

app.Run();