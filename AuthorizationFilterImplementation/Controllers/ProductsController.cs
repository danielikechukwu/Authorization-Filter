using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AuthorizationFilterImplementation.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ProductsController : ControllerBase
    {
        // Public endpoint - no authentication required
        [HttpGet("public")]
        [AllowAnonymous]
        public IActionResult GetPublicProducts()
        {            
            return Ok("This is a public endpoint accessible to everyone.");
        }

        // Authenticated users only - no role restriction
        [HttpGet("authenticated")]
        [Authorize] // Requires a valid JWT token (any authenticated user)
        public IActionResult GetAuthenticatedProducts()
        {
            var userName = User.Identity?.Name ?? "Unknown";
            return Ok($"Hello {userName}, you are authenticated and can access this endpoint.");
        }

        // Single Role Authorization - Admin only
        [HttpGet("admin")]
        [Authorize(Roles = "Admin")]
        public IActionResult AdminOnly()
        {
            var userName = User.Identity?.Name ?? "Unknown";
            return Ok($"Hello {userName}, you have Admin access to this endpoint.");
        }

        // Multiple Roles - AND Logic (User must have both Manager and Admin)
        [HttpGet("manager-and-admin")]
        [Authorize(Roles = "Admin")] // User must have BOTH Admin AND Manager roles
        [Authorize(Roles = "Manager")]
        public IActionResult ManagerAndAdmin()
        {
            var userName = User.Identity?.Name ?? "Unknown";
            return Ok($"Hello {userName}, you have both Admin and Manager roles to access this endpoint.");
        }

        // Multiple Roles - OR Logic (User must have Manager OR User)
        [HttpGet("manager-or-user")]
        [Authorize(Roles = "Manager,User")] // User must have EITHER Manager OR User role
        public IActionResult ManagerOrUser()
        {
            var userName = User.Identity?.Name ?? "Unknown";
            return Ok($"Hello {userName}, you have either Manager or User role to access this endpoint.");
        }
    }
}
