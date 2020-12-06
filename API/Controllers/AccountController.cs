using System.Threading.Tasks;
using API.Data;
using API.Entities;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;
using API.DTOs;
using Microsoft.EntityFrameworkCore;
using API.Interface;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;
        
        private readonly ITokenService _tokenService;
    

        public AccountController(DataContext context, ITokenService tokenService)
        {
            this._context = context;
            _tokenService = tokenService;
        }

        [HttpPost("register")]
        public async Task<ActionResult<UserDto>> Register(RegisterDto registerdto)
        {
            using var hmac = new HMACSHA512();

            if (await Userexists(registerdto.Username))  return BadRequest("Username still exists"); 

            var user = new AppUser()
            {
                   UserName = registerdto.Username.ToLower(),
                   PasswordHash  = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerdto.Password)),
                   PasswordSalt  = hmac.Key
            };

            _context.Add(user);
            await _context.SaveChangesAsync();

            return new UserDto
            {
                Username = user.UserName,
                Token = _tokenService.createToken(user)
            };
        }

        private async Task<bool> Userexists(string username)
        {
            return await _context.Users.AnyAsync(x => x.UserName == username.ToLower());
        }


        
        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto logindto)
        {
            AppUser user;
            user = await _context.Users.SingleOrDefaultAsync(x => x.UserName == logindto.Username);

            if (user == null) return Unauthorized("User not found");

            var hmac = new HMACSHA512(user.PasswordSalt);
            var hashedpw = hmac.ComputeHash(Encoding.UTF8.GetBytes(logindto.Password));

            for(int i = 0 ; i < user.PasswordHash.Length; i++)
            {
                if (user.PasswordHash[i] != hashedpw[i]) return Unauthorized("Wrong password;");
            }

            return new UserDto
            {
                Username = user.UserName,
                Token = _tokenService.createToken(user)
            };
        }
    }
}