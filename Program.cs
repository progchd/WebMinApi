using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using BCrypt.Net;
using WebMinApi.Models;
using System.Security.Cryptography;
using System.Linq;

var builder = WebApplication.CreateBuilder(args);

// ==========================================
// IN-MEMORY STATIC DATA STORES (Replaces Redis)
// ==========================================
// Using ConcurrentDictionary ensures thread safety for parallel API requests
var staticUsers = new ConcurrentDictionary<string, User>();

// Store hashed refresh-token -> metadata (email, expiry, revoked)
var staticRefreshTokens = new ConcurrentDictionary<string, RefreshTokenInfo>(); // Key: RefreshTokenHash, Value: metadata

// Reset tokens kept in-memory for demo (token => (email, expiry)). In real apps store hashed too and send emails.
var staticResetTokens = new ConcurrentDictionary<string, (string Email, DateTime Expires)>(); // Key: ResetToken, Value: (Email, Expiry)
var staticServiceCatalog = new List<ServiceCategory>();

// Seed the service catalog data directly in-memory on startup
SeedStaticServiceCatalog(staticServiceCatalog);

// ==========================================
// CONFIGURATION & AUTHENTICATION SERVICES
// ==========================================
// Fallback defaults used if not found in appsettings.json
var jwtKey = builder.Configuration["Jwt:Key"] ?? "A_Very_Long_And_Super_Secure_Secret_Key_2026_!";
var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? "MyWebsite";
var jwtAudience = builder.Configuration["Jwt:Audience"] ?? "MyWebsiteUsers";
var keyBytes = Encoding.ASCII.GetBytes(jwtKey);

// Add CORS Policy to allow your React App (running on port 5173) to reach this API
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowReactApp", policy => 
        policy.WithOrigins("http://localhost:5173")
              .AllowAnyHeader()
              .AllowAnyMethod());
});

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtIssuer,
        ValidAudience = jwtAudience,
        IssuerSigningKey = new SymmetricSecurityKey(keyBytes),
        ClockSkew = TimeSpan.Zero
    };
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "My API V1");
    c.RoutePrefix = "swagger"; // This ensures it loads at /swagger
});

// Enable Middleware
app.UseCors("AllowReactApp");
app.UseAuthentication();
app.UseAuthorization();

// ==========================================
// ENDPOINTS
// ==========================================

// 1. REGISTER USER
app.MapPost("/api/auth/register", (RegisterRequest request) =>
{
    if (request is null || string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password) || string.IsNullOrWhiteSpace(request.Username))
        return Results.BadRequest(new { message = "Username, email and password are required." });

    var normalizedEmail = request.Email.ToLower().Trim();

    if (staticUsers.ContainsKey(normalizedEmail))
    {
        return Results.BadRequest(new { message = "Email is already registered." });
    }

    if (request.Password.Length < 6)
    {
        return Results.BadRequest(new { message = "Password must be at least 6 characters long." });
    }

    var newUser = new User
    {
        Username = request.Username.Trim(),
        Email = normalizedEmail,
        PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password)
    };

    staticUsers[normalizedEmail] = newUser;
    return Results.Ok(new { message = "Registration successful." });
});

// 2. LOGIN USER
app.MapPost("/api/auth/login", (LoginRequest request) =>
{
    if (request is null || string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
        return Results.BadRequest(new { message = "Email and password are required." });

    var normalizedEmail = request.Email.ToLower().Trim();

    if (!staticUsers.TryGetValue(normalizedEmail, out var user))
    {
        return Results.BadRequest(new { message = "Invalid credentials." });
    }

    if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
    {
        return Results.BadRequest(new { message = "Invalid credentials." });
    }

    // Generate Tokens
    var accessToken = GenerateAccessToken(user, jwtKey, jwtIssuer, jwtAudience);

    // Use a cryptographically secure refresh token and store only its hash/server-side metadata
    var refreshToken = GenerateSecureToken();
    var refreshHash = HashToken(refreshToken);
    var refreshInfo = new RefreshTokenInfo(user.Email, DateTime.UtcNow.AddDays(7), Revoked: false);
    staticRefreshTokens[refreshHash] = refreshInfo;

    return Results.Ok(new AuthResponse(accessToken, refreshToken, user.Username));
});

// 3. GET ACCESS TOKEN USING REFRESH TOKEN
// This endpoint must be callable without a valid access token (client presents refresh token instead)
app.MapPost("/api/auth/refresh", (RefreshTokenRequest request) =>
{
    if (request is null || string.IsNullOrWhiteSpace(request.RefreshToken))
        return Results.BadRequest(new { message = "Refresh token is required." });

    var incomingHash = HashToken(request.RefreshToken);

    if (!staticRefreshTokens.TryGetValue(incomingHash, out var stored))
        return Results.Unauthorized();

    if (stored.Revoked || stored.Expires < DateTime.UtcNow)
    {
        // Remove expired/revoked token
        staticRefreshTokens.TryRemove(incomingHash, out _);
        return Results.Unauthorized();
    }

    if (!staticUsers.TryGetValue(stored.Email, out var user))
    {
        // User no longer exists
        staticRefreshTokens.TryRemove(incomingHash, out _);
        return Results.Unauthorized();
    }

    // Revoke old refresh token & issue a new one (Token Rotation)
    staticRefreshTokens.TryRemove(incomingHash, out _);

    var newRefreshToken = GenerateSecureToken();
    var newHash = HashToken(newRefreshToken);
    staticRefreshTokens[newHash] = new RefreshTokenInfo(user.Email, DateTime.UtcNow.AddDays(7), Revoked: false);

    var newAccessToken = GenerateAccessToken(user, jwtKey, jwtIssuer, jwtAudience);

    return Results.Ok(new AuthResponse(newAccessToken, newRefreshToken, user.Username));
});

// 4. FORGOT PASSWORD
// Make this endpoint anonymous; do not reveal whether the email exists.
app.MapPost("/api/auth/forgot-password", (ForgotPasswordRequest request) =>
{
    if (request is null || string.IsNullOrWhiteSpace(request.Email))
        return Results.BadRequest(new { message = "Email is required." });

    var normalizedEmail = request.Email.ToLower().Trim();

    if (!staticUsers.ContainsKey(normalizedEmail))
    {
        // For security, do not explicitly reveal if email does not exist
        return Results.Ok(new { message = "If the email exists, password reset instructions will be sent." });
    }

    // Create a temporary token valid for 15 minutes
    var resetToken = GenerateSecureToken();
    staticResetTokens[resetToken] = (normalizedEmail, DateTime.UtcNow.AddMinutes(15));

    // Development-only: log the token. DO NOT log tokens in production.
    app.Logger.LogInformation("[DEV ONLY] Reset token for {Email}: {Token}", normalizedEmail, resetToken);

    return Results.Ok(new { message = "If the email exists, password reset instructions will be sent." });
});

// 5. SERVICES & SERVICE CATEGORIES
app.MapGet("/api/services", () =>
{
    return Results.Ok(staticServiceCatalog);
}).RequireAuthorization();

// 4. SERVICES & SERVICE CATEGORIES
// 5. SERVICES & SERVICE CATEGORIES
app.MapGet("/api/say-hello", () =>
{
    return Results.Ok("Hello, world!");
}).RequireAuthorization();

// Get services for a selected category (case-insensitive Id match)
app.MapGet("/api/services/{categoryId}/items", (string categoryId) =>
{
    if (string.IsNullOrWhiteSpace(categoryId))
        return Results.BadRequest(new { message = "Category id is required." });

    var category = staticServiceCatalog.FirstOrDefault(c => string.Equals(c.Id, categoryId, StringComparison.OrdinalIgnoreCase));
    if (category is null)
        return Results.NotFound(new { message = "Service category not found." });

    return Results.Ok(category.Services);
}).RequireAuthorization();

app.Run();

// ==========================================
// HELPER METHODS
// ==========================================

string GenerateAccessToken(User user, string secretKey, string issuer, string audience)
{
    var tokenHandler = new JwtSecurityTokenHandler();
    var key = Encoding.ASCII.GetBytes(secretKey);
    
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Email, user.Email)
        }),
        Expires = DateTime.UtcNow.AddMinutes(15), // 15 Minute short lifespan
        Issuer = issuer,
        Audience = audience,
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
    };

    var token = tokenHandler.CreateToken(tokenDescriptor);
    return tokenHandler.WriteToken(token);
}

string GenerateSecureToken(int size = 64)
{
    var bytes = new byte[size];
    using var rng = RandomNumberGenerator.Create();
    rng.GetBytes(bytes);
    // Base64url (no padding) to make token URL safe
    return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

string HashToken(string token)
{
    using var sha = SHA256.Create();
    var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(token));
    return Convert.ToHexString(bytes);
}

void SeedStaticServiceCatalog(List<ServiceCategory> catalog)
{
    catalog.AddRange(new List<ServiceCategory>
    {
        new ServiceCategory
        {
            Id = "cat1",
            Name = "Web Development",
            Services = new List<ServiceItem>
            {
                new ServiceItem { Id = "s1", Name = "Single Page Application", Description = "React frontend applications built with Vite and optimized for SEO." },
                new ServiceItem { Id = "s2", Name = "Server-side Rendering", Description = "SEO-friendly server-side rendered web apps using .NET and Node.js." },
                new ServiceItem { Id = "s3", Name = "Progressive Web App", Description = "Offline-capable PWAs with service workers and caching strategies." },
                new ServiceItem { Id = "s4", Name = "Frontend Performance Tuning", Description = "Asset bundling, code splitting and runtime optimizations." },
                new ServiceItem { Id = "s5", Name = "Accessibility Audits", Description = "WCAG compliance checks and remediation for web accessibility." }
            }
        },
        new ServiceCategory
        {
            Id = "cat2",
            Name = "Backend Services",
            Services = new List<ServiceItem>
            {
                new ServiceItem { Id = "s6", Name = "REST API Design", Description = "Scalable REST APIs with versioning and documentation." },
                new ServiceItem { Id = "s7", Name = "GraphQL APIs", Description = "Flexible GraphQL endpoints for aggregated data needs." },
                new ServiceItem { Id = "s8", Name = "Microservices", Description = "Decomposed services with independent deployment and scaling." },
                new ServiceItem { Id = "s9", Name = "WebSockets & Realtime", Description = "Realtime messaging and push updates using SignalR or raw websockets." },
                new ServiceItem { Id = "s10", Name = "Background Jobs", Description = "Reliable background processing using queues and worker services." }
            }
        },
        new ServiceCategory
        {
            Id = "cat3",
            Name = "Mobile Development",
            Services = new List<ServiceItem>
            {
                new ServiceItem { Id = "s11", Name = "Cross-platform Apps", Description = "Xamarin / MAUI apps targeting iOS and Android from a single codebase." },
                new ServiceItem { Id = "s12", Name = "React Native", Description = "High-performance mobile apps built with React Native." },
                new ServiceItem { Id = "s13", Name = "Mobile CI/CD", Description = "Automated builds, tests and distribution pipelines for mobile." },
                new ServiceItem { Id = "s14", Name = "Push Notifications", Description = "Platform-agnostic push notification integration and scheduling." },
                new ServiceItem { Id = "s15", Name = "Performance Profiling", Description = "Memory and CPU profiling to reduce app energy consumption." }
            }
        },
        new ServiceCategory
        {
            Id = "cat4",
            Name = "UI/UX Design",
            Services = new List<ServiceItem>
            {
                new ServiceItem { Id = "s16", Name = "Design Systems", Description = "Reusable component libraries with tokens and documentation." },
                new ServiceItem { Id = "s17", Name = "Prototyping", Description = "Interactive prototypes for early user feedback and validation." },
                new ServiceItem { Id = "s18", Name = "User Research", Description = "Usability studies and persona development." },
                new ServiceItem { Id = "s19", Name = "Visual Design", Description = "High-fidelity UI layouts and branding assets." },
                new ServiceItem { Id = "s20", Name = "Interaction Design", Description = "Motion, micro-interactions and accessibility-focused flows." }
            }
        },
        new ServiceCategory
        {
            Id = "cat5",
            Name = "DevOps & Cloud",
            Services = new List<ServiceItem>
            {
                new ServiceItem { Id = "s21", Name = "Cloud Migration", Description = "Lift-and-shift or re-architecting for cloud-native platforms." },
                new ServiceItem { Id = "s22", Name = "CI/CD Pipelines", Description = "Automated build/test/deploy pipelines using GitHub Actions or Azure DevOps." },
                new ServiceItem { Id = "s23", Name = "Infrastructure as Code", Description = "Terraform or ARM/Bicep templates for repeatable infra." },
                new ServiceItem { Id = "s24", Name = "Monitoring & Observability", Description = "Logging, metrics and tracing for production reliability." },
                new ServiceItem { Id = "s25", Name = "Containerization", Description = "Docker image optimization and Kubernetes deployment patterns." }
            }
        },
        new ServiceCategory
        {
            Id = "cat6",
            Name = "Data Engineering",
            Services = new List<ServiceItem>
            {
                new ServiceItem { Id = "s26", Name = "ETL Pipelines", Description = "Robust extract-transform-load pipelines for analytics." },
                new ServiceItem { Id = "s27", Name = "Data Warehousing", Description = "Schema design and ingestion for OLAP workloads." },
                new ServiceItem { Id = "s28", Name = "Streaming", Description = "Real-time data processing using Kafka or Event Hubs." },
                new ServiceItem { Id = "s29", Name = "Data Lake Architecture", Description = "Organized raw and curated data storage solutions." },
                new ServiceItem { Id = "s30", Name = "Data Governance", Description = "Policies, lineage and security for enterprise data." }
            }
        },
        new ServiceCategory
        {
            Id = "cat7",
            Name = "AI & ML",
            Services = new List<ServiceItem>
            {
                new ServiceItem { Id = "s31", Name = "Model Training", Description = "Train custom ML models with modern toolchains." },
                new ServiceItem { Id = "s32", Name = "Model Deployment", Description = "Serve models in scalable endpoints with monitoring." },
                new ServiceItem { Id = "s33", Name = "NLP Solutions", Description = "Text processing, classification and summarization." },
                new ServiceItem { Id = "s34", Name = "Computer Vision", Description = "Image analysis and object detection pipelines." },
                new ServiceItem { Id = "s35", Name = "MLOps", Description = "Continuous training, validation and model governance." }
            }
        },
        new ServiceCategory
        {
            Id = "cat8",
            Name = "E-commerce Solutions",
            Services = new List<ServiceItem>
            {
                new ServiceItem { Id = "s36", Name = "Storefront Development", Description = "Custom storefronts with fast checkout flows." },
                new ServiceItem { Id = "s37", Name = "Payment Integration", Description = "PCI-compliant payment provider integrations." },
                new ServiceItem { Id = "s38", Name = "Catalog Management", Description = "Scalable product catalog and inventory systems." },
                new ServiceItem { Id = "s39", Name = "Subscriptions", Description = "Recurring billing and subscription lifecycle management." },
                new ServiceItem { Id = "s40", Name = "Order Fulfillment", Description = "Order processing, tracking and third-party logistics integrations." }
            }
        },
        new ServiceCategory
        {
            Id = "cat9",
            Name = "Security & Compliance",
            Services = new List<ServiceItem>
            {
                new ServiceItem { Id = "s41", Name = "Threat Modeling", Description = "Identify risks and harden architectures against threats." },
                new ServiceItem { Id = "s42", Name = "Penetration Testing", Description = "Simulated attacks to discover vulnerabilities." },
                new ServiceItem { Id = "s43", Name = "Identity & Access", Description = "Secure authentication and authorization patterns." },
                new ServiceItem { Id = "s44", Name = "Compliance Assessment", Description = "Gap analysis for standards like ISO/PCI/HIPAA." },
                new ServiceItem { Id = "s45", Name = "Secrets Management", Description = "Centralized secret storage and rotation." }
            }
        },
        new ServiceCategory
        {
            Id = "cat10",
            Name = "Content & Marketing",
            Services = new List<ServiceItem>
            {
                new ServiceItem { Id = "s46", Name = "Content Strategy", Description = "Plan content that drives engagement and conversions." },
                new ServiceItem { Id = "s47", Name = "SEO Optimization", Description = "Technical and content SEO for organic traffic growth." },
                new ServiceItem { Id = "s48", Name = "Campaign Automation", Description = "Email and ad campaign orchestration and analytics." },
                new ServiceItem { Id = "s49", Name = "Analytics & Reporting", Description = "Dashboards and insights for marketing performance." },
                new ServiceItem { Id = "s50", Name = "Creative Production", Description = "Design and media production for campaigns." }
            }
        }
    });
}