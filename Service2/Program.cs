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

var app = builder.Build();

app.UseRouting();
app.MapControllers();

app.Run();