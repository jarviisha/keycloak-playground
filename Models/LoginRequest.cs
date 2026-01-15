namespace server_app.Models;

/// <summary>
/// DTO cho request login
/// </summary>
public class LoginRequest
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}
