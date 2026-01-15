using System.Text;
using System.Text.Json;

namespace server_app.Services;

public class KeycloakService : IKeycloakService
{
    private readonly HttpClient _httpClient;
    private readonly IConfiguration _configuration;
    private readonly ILogger<KeycloakService> _logger;

    private string KeycloakBaseUrl => _configuration["Keycloak:Authority"]?.Replace("/realms/", "/") ?? "";
    private string Realm => _configuration["Keycloak:Realm"] ?? "";
    private string ClientId => _configuration["Keycloak:ClientId"] ?? "";

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
}
