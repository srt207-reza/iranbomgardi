using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace bomgardi.Services.User
{
    public class UserService:IUserService
    {
        private readonly IHttpContextAccessor _httpContextAccessor;

        public UserService(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }
    
        public object GetUserInfo()
        {
            if(_httpContextAccessor.HttpContext is not  null)
            {
                var name = _httpContextAccessor.HttpContext.User?.Identity?.Name;
                var roleClaims = _httpContextAccessor.HttpContext.User.FindAll(ClaimTypes.Role);
                var roles = roleClaims.Select(c => c.Value).ToList();

                return new { name, roles };
            }

            return null;
        }
    }
}
