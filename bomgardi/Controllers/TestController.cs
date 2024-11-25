using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace bomgardi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TestController : ControllerBase
    {
        public List<string> data { get; set; } = ["reza", "ahmad", "ali", "amin", "parham"];

        [HttpGet , Authorize(Roles = "Admin,User")]
        public ActionResult Get()
        {
            return Ok(data);
        }
    }
}
