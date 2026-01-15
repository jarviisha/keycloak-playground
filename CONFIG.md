# Hướng dẫn cấu hình ứng dụng

## Setup

1. Copy file `appsettings.Example.json` thành `appsettings.json`
2. Copy file `appsettings.Development.Example.json` thành `appsettings.Development.json` 
3. Cập nhật các giá trị cấu hình trong các file mới tạo

## Keycloak Configuration

Trong file `appsettings.json`, bạn cần cập nhật các thông tin sau:

```json
{
  "Keycloak": {
    "Authority": "http://your-keycloak-server:8080/realms/your-realm",
    "Audience": "your-client-id",
    "Realm": "your-realm",
    "ClientId": "your-client-id",
    "ClientSecret": "your-client-secret-here"
  }
}
```

### Lấy thông tin từ Keycloak Admin Console:

1. **Authority**: URL Keycloak server + realm của bạn
   - Format: `http://[keycloak-server]:8080/realms/[realm-name]`

2. **Realm**: Tên realm trong Keycloak

3. **ClientId**: Tên client đã tạo trong Keycloak

4. **ClientSecret**: 
   - Vào Keycloak Admin Console
   - Chọn Realm → Clients → Chọn client của bạn
   - Tab "Credentials" → Copy "Client Secret"
   
5. **Client Configuration Requirements**:
   - Client authentication: ON
   - Service accounts roles: Enabled
   - Authorization: Enabled (optional)
   - Grant types: Standard flow, Direct access grants, Service account roles

### Permissions để tạo user:

Client cần có các roles sau trong Service Account Roles:
- `manage-users` (realm-management)
- `create-client` (realm-management) - nếu cần tạo client
- `view-users` (realm-management)

## Security Notes

- **KHÔNG BAO GIỜ** commit file `appsettings.json` hoặc `appsettings.Development.json` lên git
- Các file này đã được thêm vào `.gitignore`
- Chỉ commit file `.Example.json` làm template
