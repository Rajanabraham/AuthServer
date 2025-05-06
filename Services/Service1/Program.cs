using Common.Logging;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
SerilogConfig.ConfigureLogging(builder);
var app = builder.Build();

app.UseRouting();
app.MapControllers();
app.Run();