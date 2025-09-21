using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using MyApiNetCore6.Models;
using MyApiNetCore6.Repositories;

namespace MyApiNetCore6.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountsController : ControllerBase
    {
        private readonly IAccountRepository accountRepo;

        public AccountsController(IAccountRepository repo)
        {
            accountRepo = repo;
        }

        [HttpPost("Register")]
        public async Task<IActionResult> SignUp(SignUpModel signUpModel)
        {
            var result = await accountRepo.SignUpAsync(signUpModel);
            if (result.Succeeded)
            {
                return Ok(result.Succeeded);
            }

            return Unauthorized();
        }

        [HttpPost("Login")]
        public async Task<IActionResult> SignIn(SignInModel signInModel)
        {
            var result = await accountRepo.SignInAsync(signInModel);

            if (string.IsNullOrEmpty(result))
            {
                return Unauthorized();
            }

            return Ok(result);
        }

        //[HttpPost("Logout")]
        //public IActionResult SignOut()
        //{
        //    // Since we're using JWT tokens, logout can be handled on the client side
        //    // by simply deleting the token. However, if you want to implement token
        //    // blacklisting or other server-side logout logic, you can do it here.
        //    return Ok("Logged out successfully");
        //}

        [HttpPost("ResetPassword")]
        public IActionResult ResetPassword()
        {
            // Implement password reset logic here
            return Ok("Password reset link has been sent to your email.");
        }

        //================= Google Authentication =================//

        [HttpGet("GoogleLogin")]
        public IActionResult GoogleLogin()
        {
            var properties = new AuthenticationProperties
            {
                RedirectUri = Url.Action("GoogleResponse"),
                Items = { { "scheme", "Google" } }
            };
            return Ok(properties.Items);
        }

        [HttpGet("GoogleResponse")]
        public async Task<IActionResult> GoogleResponse()
        {
            try
            {
                var result = await HttpContext.AuthenticateAsync("Google");

                if (!result.Succeeded || result.Principal == null)
                {
                    return BadRequest(new { message = "Google authentication failed" });
                }

                // Sử dụng repository để xử lý Google sign in
                var token = await accountRepo.GoogleSignInAsync(result.Principal);

                if (string.IsNullOrEmpty(token))
                {
                    return BadRequest(new { message = "Không thể tạo token xác thực" });
                }

                // Có thể redirect về frontend với token hoặc return JSON
                // Ví dụ redirect về frontend:
                // return Redirect($"https://yourfrontend.com/auth-success?token={token}");

                // Hoặc return JSON để test với Postman/API client:
                return Ok(new
                {
                    success = true,
                    token = token,
                    message = "Google login successful"
                });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = $"Authentication error: {ex.Message}" });
            }
        }
    }
}
