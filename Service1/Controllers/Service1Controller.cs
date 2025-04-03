﻿using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[Authorize]
[ApiController]
[Route("api/[controller]")]
public class Service1Controller : ControllerBase
{
    [HttpGet]
    public IActionResult Get()
    {
        return Ok("Hello from Service1!");
    }
}