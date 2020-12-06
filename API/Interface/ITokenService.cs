using API.Entities;

namespace API.Interface
{
    public interface ITokenService
    {
        string createToken(AppUser user);
    }
}