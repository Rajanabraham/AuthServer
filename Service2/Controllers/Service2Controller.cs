using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[Authorize]
[ApiController]
[Route("api/[controller]")]
public class Service2Controller : ControllerBase
{
    [HttpGet]
    public IActionResult Get()
    {
        return Ok("Hello from Service2!");
    }
}