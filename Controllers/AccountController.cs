using Microsoft.AspNetCore.Mvc;
using App.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Security.Claims;

namespace App.Controller;

[ApiController]
[Route("[controller]")]
public class AccountController : ControllerBase
{

  public SignInManager<ApplicationUser> signInManager { get; set; }
  public UserManager<ApplicationUser> userManager { get; set; }
  public RoleManager<IdentityRole> roleManager { get; set; }
  public IConfiguration? configuration;

  public AccountController(
    SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, 
    RoleManager<IdentityRole> roleManager,
    IConfiguration configuration)
  {
    this.signInManager = signInManager;
    this.userManager = userManager;
    this.configuration = configuration;
    this.roleManager = roleManager;
  }

  [HttpPost("Register")]
  public async Task<IActionResult> register([FromBody] SignUpModel signUpModel)
  {
    ApplicationUser applicationUser = new ApplicationUser
    {
      UserName = signUpModel.UserName,
      Email = signUpModel.Email
    };

    IdentityResult result = await userManager.CreateAsync(applicationUser, signUpModel.Password!);

    if (!result.Succeeded)
    {
      return StatusCode(StatusCodes.Status500InternalServerError, new ResponseModel {
        Success = false,
        Message = "Invalid input"
      });
    }

    if (!await roleManager.RoleExistsAsync(roleName: UserRoles.User))
    {
      await roleManager.CreateAsync(new IdentityRole(UserRoles.User));
    }

    await userManager.AddToRoleAsync(applicationUser, UserRoles.User);

    return Ok(new ResponseModel {
      Success = true,
      Message = "Created a new account"
    });
  }

  [HttpPost("RegisterAdmin")]
  public async Task<IActionResult> registerAdmin([FromBody] SignUpModel signUpModel)
  {
    ApplicationUser applicationUser = new ApplicationUser
    {
      UserName = signUpModel.UserName,
      Email = signUpModel.Email
    };

    IdentityResult result = await userManager.CreateAsync(applicationUser, signUpModel.Password!);

    if (!result.Succeeded)
    {
      System.Console.WriteLine(result);
      return StatusCode(StatusCodes.Status500InternalServerError, new ResponseModel {
        Success = false,
        Message = "Invalid input"
      });
    }

    if (!await roleManager.RoleExistsAsync(roleName: UserRoles.Admin))
    {
      await roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));
    }

    return Ok(new ResponseModel {
      Success = true,
      Message = "An Admin has been created"
    });
  }

  [HttpPost("SignIn")]
  public async Task<IActionResult> signIn([FromBody] SignInModel signInModel)
  {

    var User = await userManager.FindByNameAsync(signInModel.UserName!);
    if (User == null)
    {
      return StatusCode(StatusCodes.Status404NotFound, new ResponseModel {
        Success = false,
        Message = "User not found"
      });
    }

    var verifyPassword = await userManager.CheckPasswordAsync(User, signInModel.Password!);

    if (!verifyPassword)
    {
      return StatusCode(StatusCodes.Status404NotFound, new ResponseModel {
        Success = false,
        Message = "Username or Password is invalid"
      });
    }

    List<Claim> claims = new List<Claim>
    {
      new Claim(JwtRegisteredClaimNames.Name, signInModel.UserName!),
      new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
    };

    var roleManager = await userManager.GetRolesAsync(User);
    foreach (var role in roleManager)
    {
      System.Console.WriteLine(role);
      claims.Add(new Claim(ClaimTypes.Role, role));
    }

    SymmetricSecurityKey symmetricSecurityKey = new SymmetricSecurityKey(
      Encoding.UTF8.GetBytes(configuration!["JWT:Key"]!)
    );

    SigningCredentials signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

    JwtSecurityToken token = new JwtSecurityToken(
      issuer: configuration["JWT:Issuer"],
      audience: configuration["JWT:Audience"],
      claims: claims,
      signingCredentials: signingCredentials,
      expires: DateTime.Now.AddMinutes(15)
    );

    var result = new JwtSecurityTokenHandler().WriteToken(token);
    return Ok(new ResponseModel {
      Success = true,
      Message = "Welcome back",
      Token = result
    });
  }

  [HttpPost("role")]
  public async Task<IActionResult> getRoles([FromBody] SignInModel signInModel)
  {
    var User = await userManager.FindByNameAsync(signInModel.UserName!);
    if (User == null)
    {
      return StatusCode(StatusCodes.Status404NotFound, new ResponseModel {
        Success = false,
        Message = "User not found"
      });
    }

    var verifyPassword = await userManager.CheckPasswordAsync(User, signInModel.Password!);

    if (!verifyPassword)
    {
      return StatusCode(StatusCodes.Status404NotFound, new ResponseModel {
        Success = false,
        Message = "Username or Password is invalid"
      });
    }
    var roles = await userManager.GetRolesAsync(User);
    foreach (var role in roles)
    {
      System.Console.WriteLine(role);
    }

    return Ok();
  }
}