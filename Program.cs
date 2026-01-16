using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using server_app.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

// Đăng ký Keycloak Service
builder.Services.AddHttpClient<IKeycloakService, KeycloakService>();

// Configure Swagger with JWT support
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Keycloak Demo API", Version = "v1" });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Enter 'Bearer' [space] and then your token in the text input below.",
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

// Configure JWT Authentication with Keycloak
var keycloakConfig = builder.Configuration.GetSection("Keycloak");

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = keycloakConfig["Authority"];
        options.Audience = keycloakConfig["Audience"];
        options.RequireHttpsMetadata = false; // Set to true in production

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

        // Gọi Keycloak introspection để chắc chắn token còn hoạt động
        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = async context =>
            {
                var rawAuthorization = context.Request.Headers["Authorization"].FirstOrDefault();
                var rawToken = rawAuthorization?.Split(' ', StringSplitOptions.RemoveEmptyEntries).Last();

                if (string.IsNullOrWhiteSpace(rawToken))
                {
                    context.Fail("Thiếu bearer token");
                    return;
                }

                var keycloakService = context.HttpContext.RequestServices.GetRequiredService<IKeycloakService>();
                var validation = await keycloakService.ValidateTokenAsync(rawToken);

                if (!validation.IsValid)
                {
                    context.Fail(validation.Message ?? "Token không hợp lệ");
                    return;
                }

                var identity = context.Principal?.Identity as ClaimsIdentity;
                if (identity == null || validation.User == null)
                {
                    return;
                }

                // Bổ sung claim thiếu từ introspection
                void AddClaimIfMissing(string type, string? value)
                {
                    if (!string.IsNullOrWhiteSpace(value) && !identity.Claims.Any(c => c.Type == type && c.Value == value))
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
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>()
                    .CreateLogger("JwtBearer");
                logger.LogError(context.Exception, "Authentication failed");
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();

// Add CORS
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI();

app.UseCors();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();
