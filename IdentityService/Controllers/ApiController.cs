using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using IdentityService.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace IdentityService.Controllers
{
    [Route("[controller]/[action]")]
    public class ApiController : ControllerBase
    {
        public const string TokenKey = "token_key";
        public const string FacebookProvider = "Facebook";
        public const string GoogleProvider = "Google";
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
            var user = new ApplicationUser
            {
                UserName = email,
                Email = email
            };
            var result = await _userManager.CreateAsync(user, password);
            if (result == IdentityResult.Success)
            {
                return await Login(email, password);
            }
            else return BadRequest(result.Errors.FirstOrDefault());
        }

        [HttpPost]
        public async Task<IActionResult> LoginWithFacebook(string id, string accessToken)
        {
            var identityErrorDescriber = new IdentityErrorDescriber();
            // Validate facebook login at facebook :P
            var validateUrl = "https://graph.facebook.com/" + id + "?access_token=" + accessToken + "&fields=name,email";
            var webClient = new WebClient();
            var validateResultText = await webClient.DownloadStringTaskAsync(validateUrl);
            validateResultText = validateResultText.Replace(@"\u0040", "@");
            var validateResult = JsonConvert.DeserializeObject<Dictionary<string, object>>(validateResultText);
            if (validateResult.ContainsKey("email"))
            {
                var name = (string)validateResult["name"];
                var email = (string)validateResult["email"];
                var user = await _userManager.FindByEmailAsync(email);
                if (user != null)
                {
                    // Found user, adding login if not exists
                    var logins = await _userManager.GetLoginsAsync(user);
                    if (GetLoginInfoByProvider(logins, FacebookProvider, id) == null)
                    {
                        // Add new login for the user
                        var addLoginResult = await _userManager.AddLoginAsync(user, new UserLoginInfo(FacebookProvider, id, name));
                        if (!addLoginResult.Succeeded)
                        {
                            // Error occurs
                            return BadRequest(addLoginResult.Errors.FirstOrDefault());
                        }
                    }
                }
                else
                {
                    // Create new user by id and email
                    user = new ApplicationUser()
                    {
                        UserName = email,
                        Email = email,
                        EmailConfirmed = true
                    };
                    var createUserResult = await _userManager.CreateAsync(user);
                    if (!createUserResult.Succeeded)
                    {
                        // Error occurs
                        return BadRequest(createUserResult.Errors.FirstOrDefault());
                    }
                    else
                    {
                        // Add new login for the user
                        var addLoginResult = await _userManager.AddLoginAsync(user, new UserLoginInfo(FacebookProvider, id, name));
                        if (!addLoginResult.Succeeded)
                        {
                            // Error occurs
                            return BadRequest(addLoginResult.Errors.FirstOrDefault());
                        }
                    }
                }
                // Login success
                return Ok(new
                {
                    accessToken = new JwtSecurityTokenHandler().WriteToken(GenerateAccessToken(user)),
                    refreshToken = new JwtSecurityTokenHandler().WriteToken(GenerateRefreshToken(user))
                });
            }
            else return BadRequest(identityErrorDescriber.InvalidToken());
        }

        [HttpPost]
        public async Task<IActionResult> LoginWithGoogle(string idToken)
        {
            var identityErrorDescriber = new IdentityErrorDescriber();
            // Validate google login at google :P
            var validateUrl = "https://oauth2.googleapis.com/tokeninfo?id_token=" + idToken;
            var webClient = new WebClient();
            var validateResultText = await webClient.DownloadStringTaskAsync(validateUrl);
            validateResultText = validateResultText.Replace(@"\u0040", "@");
            var validateResult = JsonConvert.DeserializeObject<Dictionary<string, object>>(validateResultText);
            if (validateResult.ContainsKey("sub") && validateResult.ContainsKey("email"))
            {
                var id = (string)validateResult["sub"];
                var name = (string)validateResult["name"];
                var email = (string)validateResult["email"];
                var user = await _userManager.FindByEmailAsync(email);
                if (user != null)
                {
                    // Found user, adding login if not exists
                    var logins = await _userManager.GetLoginsAsync(user);
                    if (GetLoginInfoByProvider(logins, GoogleProvider, id) == null)
                    {
                        // Add new login for the user
                        var addLoginResult = await _userManager.AddLoginAsync(user, new UserLoginInfo(GoogleProvider, id, name));
                        if (!addLoginResult.Succeeded)
                        {
                            // Error occurs
                            return BadRequest(addLoginResult.Errors.FirstOrDefault());
                        }
                    }
                }
                else
                {
                    // Create new user by id and email
                    user = new ApplicationUser()
                    {
                        UserName = email,
                        Email = email,
                        EmailConfirmed = true
                    };
                    var createUserResult = await _userManager.CreateAsync(user);
                    if (!createUserResult.Succeeded)
                    {
                        // Error occurs
                        return BadRequest(createUserResult.Errors.FirstOrDefault());
                    }
                    else
                    {
                        // Add new login for the user
                        var addLoginResult = await _userManager.AddLoginAsync(user, new UserLoginInfo(GoogleProvider, id, name));
                        if (!addLoginResult.Succeeded)
                        {
                            // Error occurs
                            return BadRequest(addLoginResult.Errors.FirstOrDefault());
                        }
                    }
                }
                // Login success
                return Ok(new
                {
                    accessToken = new JwtSecurityTokenHandler().WriteToken(GenerateAccessToken(user)),
                    refreshToken = new JwtSecurityTokenHandler().WriteToken(GenerateRefreshToken(user))
                });
            }
            else return BadRequest(identityErrorDescriber.InvalidToken());
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
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JWT:RefreshToken:Key"])),
                    ValidIssuer = _config["JWT:RefreshToken:Issuer"],
                    ValidAudience = _config["JWT:RefreshToken:Audience"],
                }, out SecurityToken validatedToken);

                var jwtValidatedToken = validatedToken as JwtSecurityToken;
                var userId = jwtValidatedToken.Payload.Sub;
                // get the user to refresh token
                var user = await _userManager.FindByIdAsync(userId);

                if (user == null || !(user.Id + user.PasswordHash).Equals(jwtValidatedToken.Payload[TokenKey]))
                {
                    // User not found or user password changed, then the token revoked, so it's invalid token
                    return BadRequest(identityErrorDescriber.InvalidToken());
                }

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

        private UserLoginInfo GetLoginInfoByProvider(IList<UserLoginInfo> logins, string provider, string providerKey)
        {
            foreach (var login in logins)
            {
                if (login.LoginProvider.Equals(provider) &&
                    login.ProviderKey.Equals(providerKey))
                    return login;
            }
            return null;
        }

        private JwtSecurityToken GenerateAccessToken(ApplicationUser user)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Sub, user.Id)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JWT:AccessToken:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            return new JwtSecurityToken(
                issuer: _config["JWT:AccessToken:Issuer"],
                audience: _config["JWT:AccessToken:Audience"],
                claims: claims,
                expires: DateTime.Now.AddDays(Convert.ToDouble(_config["JWT:AccessToken:ExpireDays"]))
                    .AddHours(Convert.ToDouble(_config["JWT:AccessToken:ExpireHours"]))
                    .AddMinutes(Convert.ToDouble(_config["JWT:AccessToken:ExpireMinutes"])),
                signingCredentials: creds
            );
        }

        private JwtSecurityToken GenerateRefreshToken(ApplicationUser user)
        {
            // TODO: It not have to be JWT, may use other function which may faster
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(TokenKey, user.Id + user.PasswordHash)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JWT:RefreshToken:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            return new JwtSecurityToken(
                issuer: _config["JWT:RefreshToken:Issuer"],
                audience: _config["JWT:RefreshToken:Audience"],
                claims: claims,
                expires: DateTime.Now.AddDays(Convert.ToDouble(_config["JWT:RefreshToken:ExpireDays"]))
                    .AddHours(Convert.ToDouble(_config["JWT:RefreshToken:ExpireHours"]))
                    .AddMinutes(Convert.ToDouble(_config["JWT:RefreshToken:ExpireMinutes"])),
                signingCredentials: creds
            );

        }
    }
}
