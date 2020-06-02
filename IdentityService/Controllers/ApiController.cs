using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace IdentityService.Controllers
{
    [Route("[controller]/[action]")]
    public class ApiController : ControllerBase
    {
        private readonly IConfiguration _config;
        private readonly UserManager<IdentityUser> _userManager;

        public ApiController(
            IConfiguration config,
            UserManager<IdentityUser> userManager)
        {
            _config = config;
            _userManager = userManager;
        }

        [HttpPost]
        public async Task<IActionResult> Login(string email, string password)
        {
            var identityErrorDescriber = new IdentityErrorDescriber();
            // get the user to verifty
            var user = await _userManager.FindByEmailAsync(email);

            if (user == null) return BadRequest(identityErrorDescriber.InvalidEmail(email));

            // check the credentials
            if (await _userManager.CheckPasswordAsync(user, password))
            {
                var claims = new List<Claim>
                {
                    new Claim(JwtRegisteredClaimNames.Sub, email),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JwtKey"]));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
                var expires = DateTime.Now.AddSeconds(Convert.ToDouble(_config["JwtExpireSeconds"]));

                var token = new JwtSecurityToken(
                    issuer: _config["JwtIssuer"],
                    audience: _config["JwtAudience"],
                    claims: claims,
                    expires: expires,
                    signingCredentials: creds
                );

                return Ok(new JwtSecurityTokenHandler().WriteToken(token));
            }
            else return BadRequest(identityErrorDescriber.PasswordMismatch());
        }

        [HttpPost]
        public async Task<IActionResult> Register(string email, string password)
        {
            var user = new IdentityUser { UserName = email, Email = email };
            var result = await _userManager.CreateAsync(user, password);
            if (result == IdentityResult.Success)
            {
                return await Login(email, password);
            }
            else return BadRequest(result.Errors.FirstOrDefault());
        }
    }
}
