namespace WebMinApi.Models;

public record RefreshTokenInfo(string Email, DateTime Expires, bool Revoked = false);
