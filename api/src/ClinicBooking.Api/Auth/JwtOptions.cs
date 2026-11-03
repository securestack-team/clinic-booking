namespace ClinicBooking.Api.Auth;

public sealed class JwtOptions
{
    public const string SectionName = "Jwt";

    public required string Key { get; init; }

    public required string Issuer { get; init; }

    public required string Audience { get; init; }

    public int AccessTokenMinutes { get; init; } = 15;
}
