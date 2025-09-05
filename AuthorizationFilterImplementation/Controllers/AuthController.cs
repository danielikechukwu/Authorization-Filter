using AuthorizationFilterImplementation.DTOs;
using AuthorizationFilterImplementation.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthorizationFilterImplementation.Controllers
{

    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        // In-memory hardcoded users list for demo (simulate a user database)
        private readonly List<User> _user = new List<User>() {
            new User {Id = 1, Email ="Alice@Example.com", Name = "Alice", Password = "alice123", Roles = "Admin,Manager" },
            new User {Id = 2, Email ="Bob@Example.com", Name = "Bob", Password = "bob123", Roles = "User" },
            new User {Id = 3, Email ="Charlie@Example.com", Name = "Charlie", Password = "charlie123", Roles = "Manager,User" }
        };

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public IActionResult Login([FromBody] LoginDTO loginDTO)
        {
            // Find a user in our hardcoded list that matches the provided email and password (case-insensitive email check)
            var user = _user.FirstOrDefault(u => u.Email.Equals(loginDTO.Email, StringComparison.OrdinalIgnoreCase)
                                               && u.Password == loginDTO.Password);

            if(user == null)
            {
                // If no matching user is found, return Unauthorized (401)
                return Unauthorized("Invalid credentials");
            }

            // Create a list of claims to embed inside the JWT token for this user
            var claims = new List<Claim>
            {
                // Claim to identify the user by their email address
                new Claim(ClaimTypes.Name, user.Email),

                // Custom claim with user's unique Id
                new Claim("UserId", user.Id.ToString())
            };

            // Add claims for each role assigned to the user (roles are comma-separated string)
            var roles = user.Roles.Split(',', StringSplitOptions.RemoveEmptyEntries);

            foreach(var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role.Trim()));
            }

            // Generate a symmetric security key from the secret configured in appsettings.json
            var secretKey = _configuration.GetValue<string>("JwtSetting:SecretKey") ?? "8b1e5ddde0ad708f55df7a0517128980a21371d6839b87c9001779c6";

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));

            // Specify signing credentials using HMAC SHA256 algorithm and the generated key
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            // Create a JWT token embedding the claims, with no issuer/audience for simplicity, and expiration set to 30 minutes from now
            var token = new JwtSecurityToken(
                issuer: null, // No specific issuer specified.
                audience: null, // No specific audience specified.
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: credentials
            );

            // Serialize the JWT token to a string
            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

            // Return the JWT token string as JSON to the client
            return Ok(new { Token = tokenString });

        }
    }
}
