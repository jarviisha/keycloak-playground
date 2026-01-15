# Keycloak SSO Demo - .NET Backend

Dự án demo tích hợp Keycloak SSO với ASP.NET Core Web API.

## Cấu hình Keycloak

Cập nhật file `appsettings.Development.json` với thông tin Keycloak của bạn:

```json
{
  "Keycloak": {
    "Authority": "http://localhost:8080/realms/your-realm",
    "Audience": "your-client-id",
    "Realm": "your-realm",
    "ClientId": "your-client-id"
  }
}
```

## Cài đặt và chạy

```bash
# Restore dependencies
dotnet restore

# Build project
dotnet build

# Run project
dotnet run
```

API sẽ chạy tại: `http://localhost:5000` hoặc `https://localhost:5001`

## Endpoints

### Public (không cần authentication)
- `GET /api/auth/public` - Endpoint công khai
- `GET /api/auth/health` - Health check

### Protected (cần JWT token)
- `GET /api/auth/protected` - Endpoint được bảo vệ
- `GET /api/auth/userinfo` - Lấy thông tin user từ token

## Test với Swagger

1. Chạy ứng dụng
2. Truy cập: `http://localhost:5000/swagger`
3. Click "Authorize" và nhập token từ Keycloak:
   ```
   Bearer <your-access-token>
   ```

## Lấy token từ Keycloak

```bash
curl -X POST 'http://localhost:8080/realms/your-realm/protocol/openid-connect/token' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'client_id=your-client-id' \
  -d 'client_secret=your-client-secret' \
  -d 'grant_type=password' \
  -d 'username=your-username' \
  -d 'password=your-password'
```

## Cấu trúc project

```
server-app/
├── Controllers/
│   └── AuthController.cs     # API endpoints
├── Models/
│   └── UserInfo.cs           # Data models
├── Program.cs                # Application configuration
├── appsettings.json          # Configuration
└── server-app.csproj         # Project file
```
