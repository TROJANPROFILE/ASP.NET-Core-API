using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using MyApiNetCore6.Data;
using MyApiNetCore6.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace MyApiNetCore6.Repositories
{
    public class AccountRepository : IAccountRepository
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly IConfiguration configuration;

        public AccountRepository(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IConfiguration configuration)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.configuration = configuration;
        }

        public async Task<string> SignInAsync(SignInModel model)
        {
            var result = await signInManager.PasswordSignInAsync(model.Email, model.Password, false, false);

            if (!result.Succeeded)
            {
                return string.Empty;
            }

            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Email, model.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var authenKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Secret"]!));

            var token = new JwtSecurityToken(
                issuer: configuration["JWT:ValidIssuer"],
                audience: configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddMinutes(20),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authenKey, SecurityAlgorithms.HmacSha512Signature)
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public async Task<IdentityResult> SignUpAsync(SignUpModel model)
        {
            var user = new ApplicationUser
            {
                FirstName = model.FirstName,
                LastName = model.LastName,
                Email = model.Email,
                UserName = model.Email
            };

            return await userManager.CreateAsync(user, model.Password);
        }

        public async Task<string> GoogleSignInAsync(ClaimsPrincipal principal)
        {
            try
            {
                var email = principal.FindFirst(ClaimTypes.Email)?.Value;
                var name = principal.FindFirst(ClaimTypes.Name)?.Value;
                var givenName = principal.FindFirst(ClaimTypes.GivenName)?.Value;
                var surname = principal.FindFirst(ClaimTypes.Surname)?.Value;

                if (string.IsNullOrEmpty(email))
                {
                    return string.Empty;
                }

                // Tìm user theo email
                var user = await userManager.FindByEmailAsync(email);

                // Tạo user mới nếu chưa tồn tại
                if (user == null)
                {
                    var createResult = await CreateGoogleUserAsync(email, givenName, surname, name);
                    if (!createResult.Succeeded)
                    {
                        return string.Empty;
                    }
                    user = await userManager.FindByEmailAsync(email);
                }

                // Kiểm tra user null sau khi tạo mới
                if (user == null)
                {
                    return string.Empty;
                }

                // Tạo JWT token
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Email, email),
                    new Claim(ClaimTypes.Name, $"{user.FirstName ?? ""} {user.LastName ?? ""}".Trim()),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };

                var authenKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Secret"]!));
                var token = new JwtSecurityToken(
                    issuer: configuration["JWT:ValidIssuer"],
                    audience: configuration["JWT:ValidAudience"],
                    expires: DateTime.Now.AddMinutes(20),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(authenKey, SecurityAlgorithms.HmacSha512Signature)
                );

                return new JwtSecurityTokenHandler().WriteToken(token);
            }
            catch (Exception)
            {
                return string.Empty;
            }
        }

        public async Task<IdentityResult> CreateGoogleUserAsync(string email, string? givenName = null, string? surname = null, string? fullName = null)
        {
            try
            {
                // Handle null values safely
                var safeGivenName = givenName ?? "";
                var safeSurname = surname ?? "";
                var safeFullName = fullName ?? "";
                var safeEmail = email ?? "";

                // Tạo firstName và lastName an toàn
                string firstName;
                string lastName;

                if (!string.IsNullOrWhiteSpace(safeGivenName))
                {
                    firstName = safeGivenName;
                }
                else if (!string.IsNullOrWhiteSpace(safeFullName))
                {
                    var nameParts = safeFullName.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    firstName = nameParts.Length > 0 ? nameParts[0] : safeEmail.Split('@')[0];
                }
                else
                {
                    firstName = safeEmail.Split('@')[0];
                }

                if (!string.IsNullOrWhiteSpace(safeSurname))
                {
                    lastName = safeSurname;
                }
                else if (!string.IsNullOrWhiteSpace(safeFullName) && safeFullName.Contains(' '))
                {
                    var nameParts = safeFullName.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    lastName = nameParts.Length > 1 ? string.Join(" ", nameParts.Skip(1)) : "";
                }
                else
                {
                    lastName = "";
                }

                var user = new ApplicationUser
                {
                    FirstName = firstName,
                    LastName = lastName,
                    Email = email,
                    UserName = email,
                    EmailConfirmed = true // Google account đã được xác thực
                };

                // Tạo user mà không cần password vì dùng external login
                var result = await userManager.CreateAsync(user);

                if (result.Succeeded)
                {
                    // Thêm external login info
                    var loginInfo = new UserLoginInfo("Google", email ?? string.Empty, "Google");
                    await userManager.AddLoginAsync(user, loginInfo);
                }

                return result;
            }
            catch (Exception)
            {
                return IdentityResult.Failed(new IdentityError
                {
                    Description = "Không thể tạo tài khoản Google"
                });
            }
        }
    }
}