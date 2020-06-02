using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using IdentityService.Models;
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
        private readonly UserManager<ApplicationUser> _userManager;

        public ApiController(
            IConfiguration config,
            UserManager<ApplicationUser> userManager)
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
                // Access Token
                var claims = new List<Claim>
                {
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.Sub, user.Id)
                };

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["AccessTokenKey"]));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                var accessToken = new JwtSecurityToken(
                    issuer: _config["AccessTokenIssuer"],
                    audience: _config["AccessTokenAudience"],
                    claims: claims,
                    expires: DateTime.Now.AddSeconds(Convert.ToDouble(_config["AccessTokenExpireSeconds"])),
                    signingCredentials: creds
                );

                // Refresh Token
                claims = new List<Claim>
                {
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                    new Claim("token_key", user.Id + user.PasswordHash)
                };

                key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["RefreshTokenKey"]));
                creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                var refreshToken = new JwtSecurityToken(
                    issuer: _config["RefreshIssuer"],
                    audience: _config["RefreshAudience"],
                    claims: claims,
                    signingCredentials: creds
                );

                return Ok(new
                {
                    accessToken = new JwtSecurityTokenHandler().WriteToken(accessToken),
                    refreshToken = new JwtSecurityTokenHandler().WriteToken(refreshToken)
                });
            }
            else return BadRequest(identityErrorDescriber.PasswordMismatch());
        }

        [HttpPost]
        public async Task<IActionResult> Register(string email, string password)
        {
            var user = new ApplicationUser { UserName = email, Email = email };
            var result = await _userManager.CreateAsync(user, password);
            if (result == IdentityResult.Success)
            {
                return await Login(email, password);
            }
            else return BadRequest(result.Errors.FirstOrDefault());
        }
    }
}
