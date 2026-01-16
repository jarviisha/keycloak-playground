using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using server_app.Models;

namespace server_app.Services;

public class KeycloakService : IKeycloakService
{
    private readonly HttpClient _httpClient;
    private readonly IConfiguration _configuration;
    private readonly ILogger<KeycloakService> _logger;

    private string KeycloakBaseUrl => _configuration["Keycloak:Authority"]?.Replace("/realms/", "/") ?? "";
    private string Realm => _configuration["Keycloak:Realm"] ?? "";
    private string ClientId => _configuration["Keycloak:ClientId"] ?? "";
    private string ClientSecret => _configuration["Keycloak:ClientSecret"] ?? "";

    public KeycloakService(HttpClient httpClient, IConfiguration configuration, ILogger<KeycloakService> logger)
    {
        _httpClient = httpClient;
        _configuration = configuration;
        _logger = logger;
    }

    /// <summary>
    /// Tạo user mới trong Keycloak
    /// </summary>
    public async Task<bool> CreateUserAsync(string email, string username, string firstName, string lastName, string password)
    {
        try
        {
            // Lấy admin token
            var adminToken = await GetAdminTokenAsync();
            if (string.IsNullOrEmpty(adminToken))
            {
                _logger.LogError("Không thể lấy admin token");
                return false;
            }

            // URL để tạo user
            var createUserUrl = $"{KeycloakBaseUrl}admin/realms/{Realm}/users";

            // Dữ liệu user cần tạo
            var userDto = new
            {
                username = username,
                email = email,
                firstName = firstName,
                lastName = lastName,
                enabled = true,
                emailVerified = false,
                credentials = new[]
                {
                    new
                    {
                        type = "password",
                        value = password,
                        temporary = false
                    }
                }
            };

            var content = new StringContent(
                JsonSerializer.Serialize(userDto),
                Encoding.UTF8,
                "application/json"
            );

            // Thêm authorization header
            _httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", adminToken);

            var response = await _httpClient.PostAsync(createUserUrl, content);

            if (response.IsSuccessStatusCode)
            {
                _logger.LogInformation($"User '{username}' đã được tạo thành công");
                return true;
            }
            else
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger.LogError($"Lỗi tạo user: {response.StatusCode} - {errorContent}");
                return false;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError($"Exception khi tạo user: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Lấy token từ Keycloak bằng username và password
    /// </summary>
    public async Task<string> GetTokenAsync(string username, string password)
    {
        try
        {
            var tokenUrl = $"{KeycloakBaseUrl}realms/{Realm}/protocol/openid-connect/token";

            var tokenRequest = new Dictionary<string, string>
            {
                { "client_id", ClientId },
                { "username", username },
                { "password", password },
                { "grant_type", "password" }
            };

            var content = new FormUrlEncodedContent(tokenRequest);
            var response = await _httpClient.PostAsync(tokenUrl, content);

            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                using (JsonDocument doc = JsonDocument.Parse(responseContent))
                {
                    var token = doc.RootElement.GetProperty("access_token").GetString();
                    return token ?? string.Empty;
                }
            }
            else
            {
                _logger.LogError($"Lỗi lấy token: {response.StatusCode}");
                return string.Empty;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError($"Exception khi lấy token: {ex.Message}");
            return string.Empty;
        }
    }

    /// <summary>
    /// Kiểm tra xem user đã tồn tại hay chưa
    /// </summary>
    public async Task<bool> UserExistsAsync(string username)
    {
        try
        {
            var adminToken = await GetAdminTokenAsync();
            if (string.IsNullOrEmpty(adminToken))
                return false;

            var getUserUrl = $"{KeycloakBaseUrl}admin/realms/{Realm}/users?username={username}";

            _httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", adminToken);

            var response = await _httpClient.GetAsync(getUserUrl);

            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                using (JsonDocument doc = JsonDocument.Parse(responseContent))
                {
                    return doc.RootElement.GetArrayLength() > 0;
                }
            }

            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError($"Exception khi kiểm tra user: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Lấy admin token (sử dụng client credentials)
    /// </summary>
    private async Task<string> GetAdminTokenAsync()
    {
        try
        {
            var tokenUrl = $"{KeycloakBaseUrl}realms/{Realm}/protocol/openid-connect/token";

            // Lưu ý: Bạn cần cấu hình một client với client credentials flow trong Keycloak
            // Hoặc sử dụng username/password của admin account
            var clientSecret = _configuration["Keycloak:ClientSecret"] ?? "";
            
            var tokenRequest = new Dictionary<string, string>
            {
                { "client_id", ClientId },
                { "client_secret", clientSecret },
                { "grant_type", "client_credentials" }
            };

            var content = new FormUrlEncodedContent(tokenRequest);
            var response = await _httpClient.PostAsync(tokenUrl, content);

            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                using (JsonDocument doc = JsonDocument.Parse(responseContent))
                {
                    return doc.RootElement.GetProperty("access_token").GetString() ?? string.Empty;
                }
            }

            _logger.LogError($"Không thể lấy admin token: {response.StatusCode}");
            return string.Empty;
        }
        catch (Exception ex)
        {
            _logger.LogError($"Exception khi lấy admin token: {ex.Message}");
            return string.Empty;
        }
    }

    /// <summary>
    /// Introspect token trực tiếp với Keycloak
    /// </summary>
    public async Task<TokenValidationResponse> ValidateTokenAsync(string token)
    {
        try
        {
            var introspectUrl = $"{KeycloakBaseUrl}realms/{Realm}/protocol/openid-connect/token/introspect";

            var request = new Dictionary<string, string>
            {
                { "client_id", ClientId },
                { "client_secret", ClientSecret },
                { "token", token }
            };

            var response = await _httpClient.PostAsync(introspectUrl, new FormUrlEncodedContent(request));

            if (!response.IsSuccessStatusCode)
            {
                var error = await response.Content.ReadAsStringAsync();
                _logger.LogWarning("Introspection failed {Status}: {Error}", response.StatusCode, error);
                return new TokenValidationResponse { IsValid = false, Message = "Không xác thực được token với Keycloak" };
            }

            var body = await response.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            if (!root.TryGetProperty("active", out var active) || !active.GetBoolean())
            {
                return new TokenValidationResponse { IsValid = false, Message = "Token đã hết hạn hoặc không hợp lệ" };
            }

            var user = new UserInfo
            {
                Id = root.TryGetProperty("sub", out var sub) ? sub.GetString() : null,
                Username = root.TryGetProperty("preferred_username", out var username) ? username.GetString() : null,
                Email = root.TryGetProperty("email", out var email) ? email.GetString() : null,
                Name = root.TryGetProperty("name", out var name) ? name.GetString() : null,
                GivenName = root.TryGetProperty("given_name", out var givenName) ? givenName.GetString() : null,
                FamilyName = root.TryGetProperty("family_name", out var familyName) ? familyName.GetString() : null,
                Roles = new List<string>()
            };

            // Lấy roles từ realm_access
            if (root.TryGetProperty("realm_access", out var realmAccess) &&
                realmAccess.TryGetProperty("roles", out var realmRoles) &&
                realmRoles.ValueKind == JsonValueKind.Array)
            {
                foreach (var role in realmRoles.EnumerateArray())
                {
                    var value = role.GetString();
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        user.Roles.Add(value);
                    }
                }
            }

            // Lấy roles từ resource_access
            if (root.TryGetProperty("resource_access", out var resourceAccess) &&
                resourceAccess.ValueKind == JsonValueKind.Object)
            {
                foreach (var resource in resourceAccess.EnumerateObject())
                {
                    if (resource.Value.TryGetProperty("roles", out var resourceRoles) && resourceRoles.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var role in resourceRoles.EnumerateArray())
                        {
                            var value = role.GetString();
                            if (!string.IsNullOrWhiteSpace(value) && !user.Roles.Contains(value))
                            {
                                user.Roles.Add(value);
                            }
                        }
                    }
                }
            }

            return new TokenValidationResponse
            {
                IsValid = true,
                Message = "Token hợp lệ",
                User = user
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception khi introspect token");
            return new TokenValidationResponse { IsValid = false, Message = "Lỗi khi kiểm tra token" };
        }
    }
}
