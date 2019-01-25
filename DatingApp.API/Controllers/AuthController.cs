using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using DatingApp.API.Data;
using DatingApp.API.Dtos;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DatingApp.API.Controllers
{
    [Route("api/[Controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthRepositoty _repo;
        private readonly IConfiguration _config;

        public AuthController(IAuthRepositoty repo, IConfiguration config)
        {
            _repo = repo;
            _config = config;
            
        }
        [HttpPost("login")]
         public async Task<IActionResult> Login(UserForRegisterDto userForRegisterDto)
         {
           var userFromRepo = await _repo.Login(userForRegisterDto.Username.ToLower(),userForRegisterDto.Password);
           if(userFromRepo == null) return Unauthorized();

           var claim = new[]
           {
            new Claim(ClaimTypes.NameIdentifier , userFromRepo.Id.ToString()),
            new Claim(ClaimTypes.Name,userFromRepo.Username)
           };
           var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.GetSection("AppSetting:Token").Value));
           var creds = new SigningCredentials(key,SecurityAlgorithms.HmacSha512Signature);

           var tokenDescriptor = new SecurityTokenDescriptor
           {
             Subject = new ClaimsIdentity(claim),
             Expires = DateTime.Now.AddDays(1),
             SigningCredentials = creds
           };
           
           var tokenHandler = new JwtSecurityTokenHandler();

           var token = tokenHandler.CreateToken(tokenDescriptor);

           return Ok( new {
               token = tokenHandler.WriteToken(token)
           });
        
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(UserForRegisterDto userForRegisterDto)
        {
           //Validation
           userForRegisterDto.Username = userForRegisterDto.Username.ToLower();
           if(await _repo.UserExists(userForRegisterDto.Username))
             return BadRequest("User all ready exist!");
            
             var userToCreated = new User 
             {
               Username = userForRegisterDto.Username
             };

             var createdUser = await _repo.Register(userToCreated,userForRegisterDto.Password);

             return StatusCode(201);

        }
    }
}