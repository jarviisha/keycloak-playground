# Hướng dẫn tích hợp Keycloak Authentication cho dự án .NET

> Tài liệu này hướng dẫn chi tiết cách tích hợp xác thực Keycloak với Token Introspection vào các dự án .NET backend (ASP.NET Core Web API).

## Mục lục

1. [Giới thiệu](#giới-thiệu)
2. [Cấu hình Keycloak](#cấu-hình-keycloak)
3. [Cài đặt Dependencies](#cài-đặt-dependencies)
4. [Cấu hình appsettings.json](#cấu-hình-appsettingsjson)
5. [Tạo Models](#tạo-models)
6. [Tạo Keycloak Service](#tạo-keycloak-service)
7. [Cấu hình Authentication Pipeline](#cấu-hình-authentication-pipeline)
8. [Sử dụng Authorization](#sử-dụng-authorization)
9. [Testing](#testing)
10. [Best Practices](#best-practices)
11. [Troubleshooting](#troubleshooting)

---

## Giới thiệu

Giải pháp này tích hợp Keycloak vào .NET bằng cách:
- **Validate JWT token** thông qua chữ ký và issuer/audience
- **Introspect token** trực tiếp với Keycloak để đảm bảo token còn active (chưa bị revoke)
- **Lấy thông tin user và roles** từ Keycloak response
- **Tự động thêm claims** vào `ClaimsPrincipal` để dễ sử dụng trong controllers

### Ưu điểm so với chỉ validate JWT thông thường

| Tính năng | JWT Validation Only | JWT + Keycloak Introspection |
|-----------|---------------------|------------------------------|
| Kiểm tra chữ ký token | ✅ | ✅ |
| Kiểm tra expiration | ✅ | ✅ |
| Phát hiện token bị revoke | ❌ | ✅ |
| Real-time role/permission changes | ❌ | ✅ |
| User logout tức thì | ❌ | ✅ |

---

## Cấu hình Keycloak

### 1. Tạo Realm

1. Đăng nhập vào Keycloak Admin Console
2. Click **Add realm** → Đặt tên (ví dụ: `my-realm`)

### 2. Tạo Client

1. Vào **Clients** → **Create**
2. **Client ID**: `my-backend-api` (giá trị này sẽ dùng trong appsettings)
3. **Client Protocol**: `openid-connect`
4. Click **Save**

### 3. Cấu hình Client Settings

Sau khi tạo, vào tab **Settings**:

```
Client ID: my-backend-api
Client Protocol: openid-connect
Access Type: confidential    ← Quan trọng để có client secret
Standard Flow Enabled: ON
Direct Access Grants Enabled: ON
Service Accounts Enabled: ON  ← Cần thiết cho introspection
Authorization Enabled: OFF (hoặc ON nếu cần fine-grained permissions)
```

Click **Save** → Tab **Credentials** sẽ xuất hiện → Copy **Secret** (cần dùng cho introspection).

### 4. Cấu hình Roles (Optional)

1. Vào **Roles** → **Add Role**
2. Tạo các role: `admin`, `user`, `manager`...
3. Assign roles cho users qua **Users** → chọn user → **Role Mappings**

### 5. Lấy thông tin cấu hình

- **Authority/Issuer**: `http://localhost:8080/realms/my-realm`
- **Token URL**: `http://localhost:8080/realms/my-realm/protocol/openid-connect/token`
- **Introspect URL**: `http://localhost:8080/realms/my-realm/protocol/openid-connect/token/introspect`
- **Client ID**: `my-backend-api`
- **Client Secret**: (lấy từ tab Credentials)

---

## Cài đặt Dependencies

### Tạo project mới (nếu chưa có)

```bash
dotnet new webapi -n MyKeycloakApi
cd MyKeycloakApi
```

### Cài đặt NuGet packages

```bash
# JWT Bearer Authentication
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer

# HTTP Client (built-in với .NET 6+)
# dotnet add package Microsoft.Extensions.Http
```

Hoặc thêm trực tiếp vào `.csproj`:

```xml
<ItemGroup>
  <PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" Version="8.0.0" />
</ItemGroup>
```

---

## Cấu hình appsettings.json

Thêm section Keycloak vào `appsettings.json`:

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "AllowedHosts": "*",
  "Keycloak": {
    "Authority": "http://localhost:8080/realms/my-realm",
    "Realm": "my-realm",
    "ClientId": "my-backend-api",
    "ClientSecret": "your-client-secret-here",
    "Audience": "my-backend-api"
  }
}
```

**Lưu ý**:
- `Authority`: URL của realm, dùng để validate issuer
- `Realm`: Tên realm
- `ClientId`: Client ID đã tạo ở Keycloak
- `ClientSecret`: Secret từ tab Credentials của client
- `Audience`: Thường trùng với ClientId

Cho **production**, nên dùng **User Secrets** hoặc **Azure Key Vault**:

```bash
dotnet user-secrets init
dotnet user-secrets set "Keycloak:ClientSecret" "your-secret"
```

---

## Tạo Models

### UserInfo.cs

```csharp
namespace MyKeycloakApi.Models;

public class UserInfo
{
    public string? Id { get; set; }
    public string? Username { get; set; }
    public string? Email { get; set; }
    public string? Name { get; set; }
    public string? GivenName { get; set; }
    public string? FamilyName { get; set; }
    public List<string> Roles { get; set; } = new();
}
```

### TokenValidationResponse.cs

```csharp
namespace MyKeycloakApi.Models;

public class TokenValidationResponse
{
    public bool IsValid { get; set; }
    public string? Message { get; set; }
    public UserInfo? User { get; set; }
}
```

### LoginRequest.cs (nếu cần login endpoint)

```csharp
namespace MyKeycloakApi.Models;

public class LoginRequest
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}
```

---

## Tạo Keycloak Service

### 1. Interface: IKeycloakService.cs

```csharp
using MyKeycloakApi.Models;

namespace MyKeycloakApi.Services;

public interface IKeycloakService
{
    /// <summary>
    /// Gọi introspection endpoint của Keycloak để kiểm tra token còn hiệu lực
    /// </summary>
    Task<TokenValidationResponse> ValidateTokenAsync(string token);
    
    /// <summary>
    /// Lấy access token từ Keycloak bằng username và password
    /// </summary>
    Task<string> GetTokenAsync(string username, string password);
}
```

### 2. Implementation: KeycloakService.cs

```csharp
using System.Text.Json;
using MyKeycloakApi.Models;

namespace MyKeycloakApi.Services;

public class KeycloakService : IKeycloakService
{
    private readonly HttpClient _httpClient;
    private readonly IConfiguration _configuration;
    private readonly ILogger<KeycloakService> _logger;

    private string KeycloakBaseUrl => _configuration["Keycloak:Authority"]?.Replace("/realms/", "/") ?? "";
    private string Realm => _configuration["Keycloak:Realm"] ?? "";
    private string ClientId => _configuration["Keycloak:ClientId"] ?? "";
    private string ClientSecret => _configuration["Keycloak:ClientSecret"] ?? "";

    public KeycloakService(
        HttpClient httpClient, 
        IConfiguration configuration, 
        ILogger<KeycloakService> logger)
    {
        _httpClient = httpClient;
        _configuration = configuration;
        _logger = logger;
    }

    /// <summary>
    /// Introspect token với Keycloak để kiểm tra active status
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

            var response = await _httpClient.PostAsync(
                introspectUrl, 
                new FormUrlEncodedContent(request)
            );

            if (!response.IsSuccessStatusCode)
            {
                var error = await response.Content.ReadAsStringAsync();
                _logger.LogWarning("Introspection failed {Status}: {Error}", 
                    response.StatusCode, error);
                return new TokenValidationResponse 
                { 
                    IsValid = false, 
                    Message = "Không xác thực được token với Keycloak" 
                };
            }

            var body = await response.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            // Kiểm tra trường "active"
            if (!root.TryGetProperty("active", out var active) || !active.GetBoolean())
            {
                return new TokenValidationResponse 
                { 
                    IsValid = false, 
                    Message = "Token đã hết hạn hoặc không hợp lệ" 
                };
            }

            // Parse thông tin user
            var user = new UserInfo
            {
                Id = root.TryGetProperty("sub", out var sub) ? sub.GetString() : null,
                Username = root.TryGetProperty("preferred_username", out var username) 
                    ? username.GetString() : null,
                Email = root.TryGetProperty("email", out var email) 
                    ? email.GetString() : null,
                Name = root.TryGetProperty("name", out var name) 
                    ? name.GetString() : null,
                GivenName = root.TryGetProperty("given_name", out var givenName) 
                    ? givenName.GetString() : null,
                FamilyName = root.TryGetProperty("family_name", out var familyName) 
                    ? familyName.GetString() : null,
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

            // Lấy roles từ resource_access (client-specific roles)
            if (root.TryGetProperty("resource_access", out var resourceAccess) &&
                resourceAccess.ValueKind == JsonValueKind.Object)
            {
                foreach (var resource in resourceAccess.EnumerateObject())
                {
                    if (resource.Value.TryGetProperty("roles", out var resourceRoles) && 
                        resourceRoles.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var role in resourceRoles.EnumerateArray())
                        {
                            var value = role.GetString();
                            if (!string.IsNullOrWhiteSpace(value) && 
                                !user.Roles.Contains(value))
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
            return new TokenValidationResponse 
            { 
                IsValid = false, 
                Message = "Lỗi khi kiểm tra token" 
            };
        }
    }

    /// <summary>
    /// Lấy token từ Keycloak bằng Resource Owner Password Credentials
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
                using var doc = JsonDocument.Parse(responseContent);
                var token = doc.RootElement.GetProperty("access_token").GetString();
                return token ?? string.Empty;
            }

            _logger.LogError("Lỗi lấy token: {StatusCode}", response.StatusCode);
            return string.Empty;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception khi lấy token");
            return string.Empty;
        }
    }
}
```

---

## Cấu hình Authentication Pipeline

### Program.cs (hoặc Startup.cs cho .NET 5)

```csharp
using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using MyKeycloakApi.Services;

var builder = WebApplication.CreateBuilder(args);

// Đăng ký controllers
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

// Đăng ký Keycloak Service với HttpClient
builder.Services.AddHttpClient<IKeycloakService, KeycloakService>();

// Cấu hình Swagger với JWT Bearer support
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo 
    { 
        Title = "My Keycloak API", 
        Version = "v1" 
    });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. " +
                      "Enter 'Bearer' [space] and then your token.",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

// Lấy cấu hình Keycloak
var keycloakConfig = builder.Configuration.GetSection("Keycloak");

// Cấu hình JWT Authentication
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = keycloakConfig["Authority"];
        options.Audience = keycloakConfig["Audience"];
        options.RequireHttpsMetadata = false; // Set true trong production với HTTPS

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = keycloakConfig["Authority"],
            ValidAudience = keycloakConfig["Audience"],
            ClockSkew = TimeSpan.FromMinutes(1)
        };

        // Hook vào pipeline để introspect token với Keycloak
        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = async context =>
            {
                // Lấy raw token từ header
                var rawAuthorization = context.Request.Headers["Authorization"]
                    .FirstOrDefault();
                var rawToken = rawAuthorization?
                    .Split(' ', StringSplitOptions.RemoveEmptyEntries)
                    .Last();

                if (string.IsNullOrWhiteSpace(rawToken))
                {
                    context.Fail("Thiếu bearer token");
                    return;
                }

                // Gọi Keycloak introspection
                var keycloakService = context.HttpContext.RequestServices
                    .GetRequiredService<IKeycloakService>();
                var validation = await keycloakService.ValidateTokenAsync(rawToken);

                if (!validation.IsValid)
                {
                    context.Fail(validation.Message ?? "Token không hợp lệ");
                    return;
                }

                // Bổ sung claims từ introspection response
                var identity = context.Principal?.Identity as ClaimsIdentity;
                if (identity == null || validation.User == null)
                {
                    return;
                }

                void AddClaimIfMissing(string type, string? value)
                {
                    if (!string.IsNullOrWhiteSpace(value) && 
                        !identity.Claims.Any(c => c.Type == type && c.Value == value))
                    {
                        identity.AddClaim(new Claim(type, value));
                    }
                }

                AddClaimIfMissing(ClaimTypes.NameIdentifier, validation.User.Id);
                AddClaimIfMissing("preferred_username", validation.User.Username);
                AddClaimIfMissing(ClaimTypes.Email, validation.User.Email);
                AddClaimIfMissing(ClaimTypes.Name, validation.User.Name);
                AddClaimIfMissing(ClaimTypes.GivenName, validation.User.GivenName);
                AddClaimIfMissing(ClaimTypes.Surname, validation.User.FamilyName);

                foreach (var role in validation.User.Roles)
                {
                    AddClaimIfMissing(ClaimTypes.Role, role);
                }
            },
            OnAuthenticationFailed = context =>
            {
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILoggerFactory>()
                    .CreateLogger("JwtBearer");
                logger.LogError(context.Exception, "Authentication failed");
                return Task.CompletedTask;
            }
        };
    });

// Cấu hình Authorization
builder.Services.AddAuthorization();

// CORS (tùy chỉnh theo nhu cầu)
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins("http://localhost:3000", "https://your-frontend.com")
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials();
    });
});

var app = builder.Build();

// Middleware pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseCors();
app.UseAuthentication();  // Phải đặt trước UseAuthorization
app.UseAuthorization();
app.MapControllers();

app.Run();
```

### Giải thích các bước trong Pipeline

1. **JWT Validation**: Middleware `JwtBearer` tự động validate chữ ký, issuer, audience, expiration
2. **OnTokenValidated Event**: Sau khi JWT hợp lệ, gọi Keycloak introspection để:
   - Kiểm tra token có bị revoke không
   - Lấy thông tin user mới nhất (roles có thể đã thay đổi)
3. **Add Claims**: Bổ sung claims vào `ClaimsPrincipal` để dùng trong controllers
4. **OnAuthenticationFailed**: Log lỗi để debug

---

## Sử dụng Authorization

### 1. Controller với [Authorize]

```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace MyKeycloakApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class SecureController : ControllerBase
{
    [HttpGet("public")]
    public IActionResult GetPublic()
    {
        return Ok(new { message = "Endpoint công khai - không cần token" });
    }

    [Authorize]
    [HttpGet("protected")]
    public IActionResult GetProtected()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var username = User.FindFirst("preferred_username")?.Value;
        var email = User.FindFirst(ClaimTypes.Email)?.Value;
        var roles = User.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList();

        return Ok(new
        {
            message = "Bạn đã xác thực thành công!",
            userId,
            username,
            email,
            roles
        });
    }

    [Authorize(Roles = "admin")]
    [HttpGet("admin-only")]
    public IActionResult GetAdminOnly()
    {
        return Ok(new { message = "Chỉ admin mới thấy được endpoint này" });
    }

    [Authorize(Roles = "admin,manager")]
    [HttpDelete("delete/{id}")]
    public IActionResult Delete(int id)
    {
        // Chỉ admin hoặc manager mới có quyền xóa
        return Ok(new { message = $"Đã xóa resource {id}" });
    }
}
```

### 2. Policy-Based Authorization

Trong `Program.cs`, thêm policies:

```csharp
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("RequireAdminRole", policy => 
        policy.RequireRole("admin"));
    
    options.AddPolicy("RequireManagerOrAdmin", policy =>
        policy.RequireRole("admin", "manager"));
    
    options.AddPolicy("RequireEmailVerified", policy =>
        policy.RequireClaim("email_verified", "true"));
});
```

Sử dụng trong controller:

```csharp
[Authorize(Policy = "RequireAdminRole")]
[HttpPost("create")]
public IActionResult Create([FromBody] CreateDto dto)
{
    return Ok(new { message = "Resource created" });
}
```

### 3. Custom Authorization Handler

Tạo requirement và handler:

```csharp
using Microsoft.AspNetCore.Authorization;

namespace MyKeycloakApi.Authorization;

// Requirement
public class MinimumAgeRequirement : IAuthorizationRequirement
{
    public int MinimumAge { get; }
    public MinimumAgeRequirement(int minimumAge) => MinimumAge = minimumAge;
}

// Handler
public class MinimumAgeHandler : AuthorizationHandler<MinimumAgeRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        MinimumAgeRequirement requirement)
    {
        var birthDateClaim = context.User.FindFirst("birthdate");
        if (birthDateClaim == null)
        {
            return Task.CompletedTask;
        }

        if (DateTime.TryParse(birthDateClaim.Value, out var birthDate))
        {
            var age = DateTime.Today.Year - birthDate.Year;
            if (age >= requirement.MinimumAge)
            {
                context.Succeed(requirement);
            }
        }

        return Task.CompletedTask;
    }
}
```

Đăng ký trong `Program.cs`:

```csharp
builder.Services.AddSingleton<IAuthorizationHandler, MinimumAgeHandler>();

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AtLeast18", policy =>
        policy.Requirements.Add(new MinimumAgeRequirement(18)));
});
```

---

## Testing

### 1. Test với Swagger

1. Chạy ứng dụng: `dotnet run`
2. Mở `https://localhost:5001/swagger`
3. Click **Authorize** button
4. Nhập token vào ô: `Bearer <your-access-token>`
5. Gọi các endpoints protected

### 2. Lấy token từ Keycloak

**Bằng curl**:

```bash
curl -X POST "http://localhost:8080/realms/my-realm/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=my-backend-api" \
  -d "username=testuser" \
  -d "password=testpass" \
  -d "grant_type=password"
```

**Bằng Postman**:

1. Method: POST
2. URL: `http://localhost:8080/realms/my-realm/protocol/openid-connect/token`
3. Body (x-www-form-urlencoded):
   - `client_id`: my-backend-api
   - `username`: testuser
   - `password`: testpass
   - `grant_type`: password

Response:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 300,
  "refresh_expires_in": 1800,
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer"
}
```

### 3. Test với HTTPie

```bash
# Lấy token
http -f POST http://localhost:8080/realms/my-realm/protocol/openid-connect/token \
  client_id=my-backend-api \
  username=testuser \
  password=testpass \
  grant_type=password

# Gọi API với token
http GET http://localhost:5001/api/secure/protected \
  "Authorization: Bearer <access-token>"
```

### 4. Unit Test

```csharp
using Xunit;
using Moq;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using MyKeycloakApi.Services;

public class KeycloakServiceTests
{
    [Fact]
    public async Task ValidateTokenAsync_WithActiveToken_ReturnsValid()
    {
        // Arrange
        var mockHttpClient = new Mock<HttpClient>();
        var mockConfig = new Mock<IConfiguration>();
        var mockLogger = new Mock<ILogger<KeycloakService>>();
        
        mockConfig.Setup(c => c["Keycloak:Authority"]).Returns("http://localhost:8080/realms/test");
        mockConfig.Setup(c => c["Keycloak:Realm"]).Returns("test");
        mockConfig.Setup(c => c["Keycloak:ClientId"]).Returns("test-client");
        mockConfig.Setup(c => c["Keycloak:ClientSecret"]).Returns("secret");

        var service = new KeycloakService(
            mockHttpClient.Object, 
            mockConfig.Object, 
            mockLogger.Object
        );

        // Act & Assert
        // TODO: Mock HttpClient response
    }
}
```

---

## Best Practices

### 1. Security

✅ **Luôn dùng HTTPS trong production**
```csharp
options.RequireHttpsMetadata = true; // Production
```

✅ **Lưu trữ ClientSecret an toàn**
- Development: User Secrets
- Production: Azure Key Vault / AWS Secrets Manager / Environment Variables

```bash
dotnet user-secrets set "Keycloak:ClientSecret" "your-secret"
```

✅ **Cấu hình CORS chặt chẽ**
```csharp
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins("https://your-frontend.com")
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});
```

✅ **Validate audience và issuer**
```csharp
ValidateIssuer = true,
ValidateAudience = true,
```

### 2. Performance

✅ **Cache introspection kết quả (nếu cần)**

Nếu bạn muốn giảm số lần gọi Keycloak, có thể cache kết quả introspection trong vài giây:

```csharp
using Microsoft.Extensions.Caching.Memory;

public class CachedKeycloakService : IKeycloakService
{
    private readonly KeycloakService _inner;
    private readonly IMemoryCache _cache;

    public CachedKeycloakService(KeycloakService inner, IMemoryCache cache)
    {
        _inner = inner;
        _cache = cache;
    }

    public async Task<TokenValidationResponse> ValidateTokenAsync(string token)
    {
        var cacheKey = $"token:{token.GetHashCode()}";
        
        if (_cache.TryGetValue(cacheKey, out TokenValidationResponse? cached))
        {
            return cached!;
        }

        var result = await _inner.ValidateTokenAsync(token);
        
        if (result.IsValid)
        {
            // Cache trong 30 giây
            _cache.Set(cacheKey, result, TimeSpan.FromSeconds(30));
        }

        return result;
    }

    public Task<string> GetTokenAsync(string username, string password)
        => _inner.GetTokenAsync(username, password);
}
```

⚠️ **Lưu ý**: Cache có thể làm trễ việc phát hiện token bị revoke.

✅ **Sử dụng HttpClientFactory**

Đã implement đúng trong code mẫu:
```csharp
builder.Services.AddHttpClient<IKeycloakService, KeycloakService>();
```

### 3. Logging

✅ **Log authentication failures**
```csharp
OnAuthenticationFailed = context =>
{
    var logger = context.HttpContext.RequestServices
        .GetRequiredService<ILoggerFactory>()
        .CreateLogger("JwtBearer");
    logger.LogError(context.Exception, "Authentication failed");
    return Task.CompletedTask;
}
```

✅ **Log introspection calls**
```csharp
_logger.LogInformation("Validating token for user {Username}", username);
```

### 4. Error Handling

✅ **Trả về thông báo lỗi rõ ràng**
```csharp
if (!validation.IsValid)
{
    return Unauthorized(new { error = validation.Message });
}
```

✅ **Catch exceptions trong services**
```csharp
try
{
    // ...
}
catch (HttpRequestException ex)
{
    _logger.LogError(ex, "HTTP error when calling Keycloak");
    return new TokenValidationResponse 
    { 
        IsValid = false, 
        Message = "Không kết nối được với Keycloak" 
    };
}
```

---

## Troubleshooting

### 1. "401 Unauthorized" khi gọi protected endpoint

**Nguyên nhân**:
- Token không được gửi trong header
- Token sai format
- Token đã hết hạn
- Issuer/Audience không khớp

**Cách fix**:
1. Kiểm tra header: `Authorization: Bearer <token>`
2. Kiểm tra token chưa hết hạn (jwt.io)
3. Kiểm tra `Authority`, `Audience` trong appsettings khớp với Keycloak
4. Xem logs: `OnAuthenticationFailed` event

### 2. "Unable to obtain configuration from Keycloak"

**Nguyên nhân**:
- URL Authority sai
- Keycloak chưa chạy
- Network không kết nối được

**Cách fix**:
1. Kiểm tra Keycloak đang chạy: `http://localhost:8080`
2. Kiểm tra Authority URL đúng: `http://localhost:8080/realms/my-realm`
3. Test endpoint: `curl http://localhost:8080/realms/my-realm/.well-known/openid-configuration`

### 3. "Token introspection failed"

**Nguyên nhân**:
- ClientSecret sai
- Client chưa enable Service Accounts

**Cách fix**:
1. Vào Keycloak Admin → Clients → Client của bạn → Settings
2. Đảm bảo **Access Type**: `confidential`
3. Đảm bảo **Service Accounts Enabled**: `ON`
4. Copy lại secret từ tab **Credentials**

### 4. Roles không xuất hiện trong claims

**Nguyên nhân**:
- Roles chưa được map vào token
- User chưa được assign role

**Cách fix**:
1. Vào Keycloak → Users → chọn user → **Role Mappings** → Assign roles
2. Vào Keycloak → Clients → client của bạn → **Mappers** tab
3. Kiểm tra có mapper cho realm roles và client roles

### 5. CORS errors

**Nguyên nhân**:
- Chưa cấu hình CORS
- Frontend origin không nằm trong whitelist

**Cách fix**:
```csharp
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins("http://localhost:3000")
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials();
    });
});

// Trong pipeline
app.UseCors(); // Phải đặt trước UseAuthentication
```

---

## Migration từ code cũ

Nếu dự án hiện tại chỉ validate JWT thông thường, bạn cần:

### 1. Thêm Keycloak Service

Tạo `Services/IKeycloakService.cs` và `Services/KeycloakService.cs` như hướng dẫn trên.

### 2. Update Program.cs

Thêm vào authentication configuration:

```csharp
// Đăng ký service
builder.Services.AddHttpClient<IKeycloakService, KeycloakService>();

// Thêm Events vào JwtBearerOptions
options.Events = new JwtBearerEvents
{
    OnTokenValidated = async context =>
    {
        // Code introspection như trên
    }
};
```

### 3. Update appsettings.json

Thêm `ClientSecret` nếu chưa có:

```json
{
  "Keycloak": {
    "Authority": "http://localhost:8080/realms/my-realm",
    "ClientId": "my-backend-api",
    "ClientSecret": "your-client-secret",
    "Audience": "my-backend-api",
    "Realm": "my-realm"
  }
}
```

### 4. Test

1. Chạy app
2. Gọi endpoint protected với token hợp lệ → OK
3. Logout user trên Keycloak Admin Console
4. Gọi lại endpoint với cùng token → 401 (token bị revoke)

---

## Kết luận

Giải pháp này mang lại:

✅ **Bảo mật cao**: Token introspection thời gian thực với Keycloak  
✅ **Dễ tích hợp**: Chỉ cần thêm service và event handler  
✅ **Linh hoạt**: Dễ mở rộng với policies và custom handlers  
✅ **Maintainable**: Code rõ ràng, dễ test  

Áp dụng pattern này vào bất kỳ dự án .NET nào cần xác thực với Keycloak!

---

**Tác giả**: Generated for .NET Keycloak Integration  
**Cập nhật**: January 2026  
**Phiên bản**: 1.0
