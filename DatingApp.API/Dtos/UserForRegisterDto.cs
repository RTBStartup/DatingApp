using System.ComponentModel.DataAnnotations;

namespace DatingApp.API.Dtos
{
    public class UserForRegisterDto
    {
        [Required]
        public string Username { get; set; }
        [StringLength(8,MinimumLength = 4,ErrorMessage="Password must be in between 8 and 4")]
        public string Password { get; set; }
    }
}