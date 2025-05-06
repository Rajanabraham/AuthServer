using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
public class Service1Controller : ControllerBase
{

 private readonly ILogger<Service1Controller> _logger;
public Service1Controller(ILogger<Service1Controller> logger)
{
        _logger = logger;
}

    [HttpGet]
    public IActionResult Get()
    {
        _logger.LogInformation("Hello from Service1");
        return Ok("Hello from Service1!");
    }
}