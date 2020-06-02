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
        public const string TokenKey = "token_key";
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
                return Ok(new
                {
                    accessToken = new JwtSecurityTokenHandler().WriteToken(GenerateAccessToken(user)),
                    refreshToken = new JwtSecurityTokenHandler().WriteToken(GenerateRefreshToken(user))
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

        [HttpPost]
        public async Task<IActionResult> RefreshAccessToken(string refreshToken)
        {
            var identityErrorDescriber = new IdentityErrorDescriber();
            var tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                tokenHandler.ValidateToken(refreshToken, new TokenValidationParameters
                {
                    ValidIssuer = _config["RefreshTokenIssuer"],
                    ValidAudience = _config["RefreshTokenAudience"],
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["RefreshTokenKey"])),
                }, out SecurityToken validatedToken);

                var jwtValidatedToken = validatedToken as JwtSecurityToken;
                var userId = jwtValidatedToken.Payload.Sub;
                // get the user to refresh token
                var user = await _userManager.FindByIdAsync(userId);

                if (user == null) return BadRequest(identityErrorDescriber.InvalidToken());

                return Ok(new
                {
                    accessToken = new JwtSecurityTokenHandler().WriteToken(GenerateAccessToken(user)),
                });
            }
            catch
            {
                return BadRequest();
            }
        }

        private JwtSecurityToken GenerateAccessToken(ApplicationUser user)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Sub, user.Id)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["AccessTokenKey"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            return new JwtSecurityToken(
                issuer: _config["AccessTokenIssuer"],
                audience: _config["AccessTokenAudience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(Convert.ToDouble(_config["AccessTokenExpireMinutes"])),
                signingCredentials: creds
            );
        }

        private JwtSecurityToken GenerateRefreshToken(ApplicationUser user)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(TokenKey, user.Id + user.PasswordHash)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["RefreshTokenKey"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            return new JwtSecurityToken(
                issuer: _config["RefreshTokenIssuer"],
                audience: _config["RefreshTokenAudience"],
                claims: claims,
                expires: DateTime.Now.AddDays(Convert.ToDouble(_config["RefreshTokenExpireDays"])),
                signingCredentials: creds
            );

        }
    }
}
