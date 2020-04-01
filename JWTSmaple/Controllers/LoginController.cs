using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using JWTSmaple.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace JWTSmaple.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {

        public IConfiguration _config;

        public LoginController(IConfiguration config)
        {
            _config = config;
        }

        [HttpGet]
        public IActionResult Login(string username, string password)
        {
            User user = new User()
            {
                UserName = username,
                Password = password
            };
            IActionResult response = Unauthorized();

            var authenticatedUser = Authenticate(user);
            if (authenticatedUser != null)
            {
                var token = GenerateJSONWebToken(authenticatedUser);
                response = Ok(new { token = token });
            }


            return response;

        }

        private object GenerateJSONWebToken(User user)
        {
            var security = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(security, SecurityAlgorithms.HmacSha256);

            var claims = new[] {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Email, user.EmailAddress),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(_config["Jwt:Issuer"], audience: _config["Jwt:Issuer"], claims, expires: DateTime.Now.AddMinutes(120), signingCredentials: credentials);

            var encodeToken = new JwtSecurityTokenHandler().WriteToken(token);

            return encodeToken;
        }

        private User Authenticate(User user)
        {
            if (user.UserName == "admin" && user.Password == "admin")
            {
                return new User { UserName = "admin", Password = "admin", EmailAddress = "admin@admin.com" };
            }
            return null;
        }

        [Authorize]
        [HttpPost]
        public string Post()
        {
            var identity = HttpContext.User.Identity as ClaimsIdentity;
            IList<Claim> claims = identity.Claims.ToList();
            var username = claims[0].Value;

            return "Welcome To:" + username;
        }

        [HttpGet("GetValue")]
        public ActionResult<IEnumerable<string>> Get()
        {
            return new string[] { "Value 1", "Value 2", "Value 3" };
        }
    }
}