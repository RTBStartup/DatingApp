using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AutoMapper;
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
        private readonly IMapper _mapper;

        public AuthController(IAuthRepositoty repo, IConfiguration config, IMapper mapper)
        {
            _repo = repo;
            _config = config;
            _mapper = mapper;
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
           
           var user = _mapper.Map<UserForListDto>(userFromRepo);

           return Ok( new {
               token = tokenHandler.WriteToken(token),
               user
           });
        
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(UserForRegisterDto userForRegisterDto)
        {
           //Validation
           userForRegisterDto.Username = userForRegisterDto.Username.ToLower();
           if(await _repo.UserExists(userForRegisterDto.Username))
             return BadRequest("User all ready exist!");
            
            var userToCreated = _mapper.Map<User>(userForRegisterDto);
            //  var userToCreated = new User 
            //  {
            //    Username = userForRegisterDto.Username
            //  };

             var createdUser = await _repo.Register(userToCreated,userForRegisterDto.Password);

             var userToReturn = _mapper.Map<UserForDetailedDto>(createdUser);

             return CreatedAtRoute("GetUser", new {Controller = "Users", id = createdUser.Id}, userToReturn);

        }
    }
}