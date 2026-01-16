using server_app.Models;

namespace server_app.Services;

public interface IKeycloakService
{
    /// <summary>
    /// Tạo user mới trong Keycloak
    /// </summary>
    Task<bool> CreateUserAsync(string email, string username, string firstName, string lastName, string password);
    
    /// <summary>
    /// Lấy token từ Keycloak bằng username và password
    /// </summary>
    Task<string> GetTokenAsync(string username, string password);
    
    /// <summary>
    /// Kiểm tra xem user đã tồn tại hay chưa
    /// </summary>
    Task<bool> UserExistsAsync(string username);

    /// <summary>
    /// Gọi introspection endpoint của Keycloak để kiểm tra token còn hiệu lực không
    /// </summary>
    Task<TokenValidationResponse> ValidateTokenAsync(string token);
}
