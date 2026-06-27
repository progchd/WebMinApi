namespace WebMinApi.Models;

// Authentication Models
public record RegisterRequest(string Username, string Email, string Password);
public record LoginRequest(string Email, string Password);
public record RefreshTokenRequest(string RefreshToken);
public record ForgotPasswordRequest(string Email);
public record AuthResponse(string AccessToken, string RefreshToken, string Username);

public class User
{
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
}

// Service Catalog Models
public class ServiceCategory
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public List<ServiceItem> Services { get; set; } = new();
}

public class ServiceItem
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
}