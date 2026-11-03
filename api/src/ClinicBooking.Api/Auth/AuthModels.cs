namespace ClinicBooking.Api.Auth;

public sealed record RegisterRequest(string Email, string Password);

public sealed record LoginRequest(string Email, string Password);

public sealed record AuthResponse(string AccessToken, DateTime ExpiresAtUtc, string Role);
