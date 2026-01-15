namespace server_app.Models;

public class UserInfo
{
    public string? Id { get; set; }
    public string? Username { get; set; }
    public string? Email { get; set; }
    public string? Name { get; set; }
    public string? GivenName { get; set; }
    public string? FamilyName { get; set; }
    public List<string> Roles { get; set; } = [];
}

public class TokenValidationResponse
{
    public bool IsValid { get; set; }
    public string? Message { get; set; }
    public UserInfo? User { get; set; }
}
