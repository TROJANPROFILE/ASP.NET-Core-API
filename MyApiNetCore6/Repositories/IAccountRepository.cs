using Microsoft.AspNetCore.Identity;
using MyApiNetCore6.Models;
using System.Security.Claims;

namespace MyApiNetCore6.Repositories
{
    public interface IAccountRepository
    {
        Task<string> SignInAsync(SignInModel model);
        Task<IdentityResult> SignUpAsync(SignUpModel model);
        Task<string> GoogleSignInAsync(ClaimsPrincipal principal);
        Task<IdentityResult> CreateGoogleUserAsync(string email, string? givenName = null, string? surname = null, string? fullName = null);
    }
}