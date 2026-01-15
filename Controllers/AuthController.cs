using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using server_app.Models;
using server_app.Services;

namespace server_app.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly ILogger<AuthController> _logger;
    private readonly IKeycloakService _keycloakService;

    public AuthController(ILogger<AuthController> logger, IKeycloakService keycloakService)
    {
        _logger = logger;
        _keycloakService = keycloakService;
    }

    /// <summary>
    /// Public endpoint - không cần authentication
    /// </summary>
    [HttpGet("public")]
    public IActionResult GetPublic()
    {
        return Ok(new
        {
            message = "Đây là endpoint public - không cần token",
            timestamp = DateTime.UtcNow
        });
    }

    /// <summary>
    /// Protected endpoint - cần JWT token từ Keycloak
    /// </summary>
    [Authorize]
    [HttpGet("protected")]
    public IActionResult GetProtected()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var userName = User.FindFirst("preferred_username")?.Value ?? User.Identity?.Name;
        var email = User.FindFirst(ClaimTypes.Email)?.Value;
        
        var claims = User.Claims.Select(c => new { c.Type, c.Value }).ToList();

        return Ok(new
        {
            message = "Bạn đã xác thực thành công!",
            userId,
            userName,
            email,
            claims,
            timestamp = DateTime.UtcNow
        });
    }

    /// <summary>
    /// Endpoint để lấy thông tin user từ token
    /// </summary>
    [Authorize]
    [HttpGet("userinfo")]
    public IActionResult GetUserInfo()
    {
        var userInfo = new
        {
            Id = User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? User.FindFirst("sub")?.Value,
            Username = User.FindFirst("preferred_username")?.Value ?? User.Identity?.Name,
            Email = User.FindFirst(ClaimTypes.Email)?.Value ?? User.FindFirst("email")?.Value,
            Name = User.FindFirst(ClaimTypes.Name)?.Value ?? User.FindFirst("name")?.Value,
            GivenName = User.FindFirst(ClaimTypes.GivenName)?.Value ?? User.FindFirst("given_name")?.Value,
            FamilyName = User.FindFirst(ClaimTypes.Surname)?.Value ?? User.FindFirst("family_name")?.Value,
            Roles = User.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList(),
            AllClaims = User.Claims.Select(c => new { c.Type, c.Value }).ToList()
        };

        return Ok(userInfo);
    }

    /// <summary>
    /// Tạo tài khoản mới trong Keycloak
    /// </summary>
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        // Validate request
        if (!ModelState.IsValid)
        {
            return BadRequest(new RegisterResponse 
            { 
                Success = false, 
                Message = "Dữ liệu không hợp lệ" 
            });
        }

        if (request.Password != request.ConfirmPassword)
        {
            return BadRequest(new RegisterResponse 
            { 
                Success = false, 
                Message = "Mật khẩu không khớp" 
            });
        }

        // Kiểm tra user đã tồn tại
        var userExists = await _keycloakService.UserExistsAsync(request.Username);
        if (userExists)
        {
            return BadRequest(new RegisterResponse 
            { 
                Success = false, 
                Message = "Username đã tồn tại" 
            });
        }

        // Tạo user
        var created = await _keycloakService.CreateUserAsync(
            request.Email,
            request.Username,
            request.FirstName,
            request.LastName,
            request.Password
        );

        if (!created)
        {
            return BadRequest(new RegisterResponse 
            { 
                Success = false, 
                Message = "Không thể tạo tài khoản. Vui lòng thử lại" 
            });
        }

        // Lấy token cho user vừa tạo
        var token = await _keycloakService.GetTokenAsync(request.Username, request.Password);

        return Ok(new RegisterResponse 
        { 
            Success = true, 
            Message = "Tài khoản đã được tạo thành công",
            Token = token
        });
    }

    /// <summary>
    /// Login endpoint - lấy token từ Keycloak
    /// </summary>
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(new { success = false, message = "Dữ liệu không hợp lệ" });
        }

        var token = await _keycloakService.GetTokenAsync(request.Username, request.Password);

        if (string.IsNullOrEmpty(token))
        {
            return Unauthorized(new { success = false, message = "Username hoặc password không chính xác" });
        }

        return Ok(new { success = true, token });
    }

    /// <summary>
    /// Health check endpoint
    /// </summary>
    [HttpGet("health")]
    public IActionResult Health()
    {
        return Ok(new { status = "healthy", service = "Keycloak Demo API" });
    }
}
