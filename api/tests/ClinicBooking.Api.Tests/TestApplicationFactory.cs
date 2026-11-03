using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace ClinicBooking.Api.Tests;

/// <summary>
/// Hôte de test commun : fournit les réglages que l'API exige au démarrage
/// (base de données et JWT), avec des valeurs réservées aux tests.
/// </summary>
public sealed class TestApplicationFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseSetting(
            "ConnectionStrings:Default",
            "Host=localhost;Database=clinic_booking_test;Username=test;Password=test");
        builder.UseSetting("Jwt:Key", "test-only-signing-key-that-is-at-least-32-bytes");
        builder.UseSetting("Jwt:Issuer", "ClinicBooking.Tests");
        builder.UseSetting("Jwt:Audience", "ClinicBooking.Tests");
    }
}
