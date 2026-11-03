using System.Security.Cryptography;
using ClinicBooking.Api.Data;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace ClinicBooking.Api.Tests;

/// <summary>
/// Hôte de test commun : fournit les réglages que l'API exige au démarrage
/// (base de données et JWT). La clé JWT est générée à chaque exécution : aucune clé dans le code.
/// </summary>
public class TestApplicationFactory : WebApplicationFactory<Program>
{
    private static readonly string JwtTestKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48));

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseSetting("ConnectionStrings:Default", "Host=localhost;Database=clinic_booking_test");
        builder.UseSetting("Jwt:Key", JwtTestKey);
        builder.UseSetting("Jwt:Issuer", "ClinicBooking.Tests");
        builder.UseSetting("Jwt:Audience", "ClinicBooking.Tests");
    }
}

/// <summary>
/// Hôte de test avec une base EF Core en mémoire à la place de PostgreSQL, pour tester
/// l'inscription et la connexion de bout en bout (Identity, rôles, JWT).
/// </summary>
public sealed class AuthTestApplicationFactory : TestApplicationFactory
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureServices(services =>
        {
            var toRemove = services.Where(d =>
                d.ServiceType == typeof(DbContextOptions<ClinicBookingDbContext>) ||
                d.ServiceType == typeof(IDbContextOptionsConfiguration<ClinicBookingDbContext>)).ToList();
            foreach (var descriptor in toRemove)
            {
                services.Remove(descriptor);
            }

            var databaseName = $"auth-tests-{Guid.NewGuid():N}";
            services.AddDbContext<ClinicBookingDbContext>(options => options.UseInMemoryDatabase(databaseName));
        });
    }
}
