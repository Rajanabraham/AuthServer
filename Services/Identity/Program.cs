
using Identity;
using Identity.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add controllers
builder.Services.AddControllers();
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    //// Configure Entity Framework Core to use Microsoft SQL Server.
    //options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));

    // Configure Entity Framework Core to use Postgre SQL Server.
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection"));


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

// Add Twilio configuration
builder.Services.Configure<TwilioSettings>(options =>
{
    options.AccountSid = builder.Configuration["Twilio:AccountSid"];
    options.AuthToken = builder.Configuration["Twilio:AuthToken"];
    options.PhoneNumber = builder.Configuration["Twilio:PhoneNumber"];
});
builder.Services.Configure<ExtensionGrantCredentials>(options =>
{
    options.AuthServer = builder.Configuration["ExtensionGrantCredentials:AuthServer"];
    options.Scope = builder.Configuration["ExtensionGrantCredentials:Scope"];
    options.ClientId = builder.Configuration["ExtensionGrantCredentials:ClientId"];
});
builder.Services.AddTransient<Seeder>();
// Add Swagger services
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("identity", new Microsoft.OpenApi.Models.OpenApiInfo
    {
        Title = "Identity"
    });
});

var app = builder.Build();
using (var scope = app.Services.CreateScope())
{
    var seeder = scope.ServiceProvider.GetRequiredService<Seeder>();
    seeder.AddClients().GetAwaiter().GetResult();
}

// Configure Swagger middleware
app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/identity/swagger.json", "Identity");
    c.RoutePrefix = string.Empty;
});

app.MapControllers();

app.Run();