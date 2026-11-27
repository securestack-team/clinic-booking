// Test de sécurité pour la branche vulnerable-demo.
// Ce test démontre que l'endpoint GET /api/demo/appointments/{id} est vulnérable au BOLA :
// un patient authentifié peut accéder au rendez-vous d'un autre patient.
//
// Le test DOIT ÉCHOUER (200 au lieu de 403) sur la branche vulnerable-demo,
// prouvant que la vulnérabilité est présente et que le scanner la détecte.
// La correction attendue : vérifier que appointment.PatientId == userId courant, sinon 403.

using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using ClinicBooking.Api.Data;
using ClinicBooking.Api.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace ClinicBooking.Api.Tests.Security;

/// <summary>
/// Tests BOLA (Broken Object Level Authorization) sur l'endpoint de démonstration.
/// Menace : OWASP API Security Top 10 : API1:2023 Broken Object Level Authorization (CWE-639).
/// Contrôle attendu : vérifier que la ressource appartient à l'utilisateur du JWT.
/// </summary>
public sealed class BolaTests : IClassFixture<BolaTestApplicationFactory>
{
    private readonly BolaTestApplicationFactory _factory;

    public BolaTests(BolaTestApplicationFactory factory)
    {
        _factory = factory;
    }

    /// <summary>
    /// Un patient A peut lire ses propres rendez-vous : 200 attendu.
    /// </summary>
    [Fact]
    public async Task Owner_CanReadOwnAppointment()
    {
        var (patientAId, appointmentId) = await _factory.SeedAsync();
        var client = _factory.CreateAuthenticatedClient(patientAId, "Patient");

        using var response = await client.GetAsync($"/api/demo/appointments/{appointmentId}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    /// <summary>
    /// BOLA : un patient B accède au rendez-vous de A — ce test démontre la faille.
    /// Sur la branche vulnerable-demo, l'endpoint retourne 200 au lieu de 403.
    /// Ce test DOIT donc échouer pour prouver que la vulnérabilité est présente.
    ///
    /// Ce comportement est intentionnel dans cette branche de démonstration.
    /// La correction : vérifier appointment.PatientId == userId courant dans DemoController.
    /// </summary>
    [Fact]
    public async Task OtherPatient_CanAccessAnotherPatientAppointment_DemoBola()
    {
        var (patientAId, appointmentId) = await _factory.SeedAsync();
        // Patient B : identité différente de celle du propriétaire du rendez-vous.
        var clientB = _factory.CreateAuthenticatedClient("patient-b-" + Guid.NewGuid().ToString("N"), "Patient");

        using var response = await clientB.GetAsync($"/api/demo/appointments/{appointmentId}");

        // Sur la branche corrigée, ce serait 403 Forbidden.
        // Sur cette branche vulnérable, l'endpoint répond 200 — ce qui PROUVE la faille BOLA.
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); // ← échoue intentionnellement
    }

    /// <summary>
    /// Sans token : 401 — l'endpoint exige quand même une authentification.
    /// </summary>
    [Fact]
    public async Task Unauthenticated_CannotReadAppointment()
    {
        var (_, appointmentId) = await _factory.SeedAsync();
        using var client = _factory.CreateClient();

        using var response = await client.GetAsync($"/api/demo/appointments/{appointmentId}");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}

/// <summary>
/// Factory de test pour les tests BOLA : base en mémoire, JWT généré localement.
/// </summary>
public sealed class BolaTestApplicationFactory : TestApplicationFactory
{
    private static readonly string TestKey = Convert.ToBase64String(
        System.Security.Cryptography.RandomNumberGenerator.GetBytes(48));

    private Guid _seededAppointmentId = Guid.Empty;
    private string _seededPatientId = string.Empty;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.UseSetting("Jwt:Key", TestKey);
        builder.ConfigureServices(services =>
        {
            // Remplace PostgreSQL par une base en mémoire isolée.
            var toRemove = services.Where(d =>
                d.ServiceType == typeof(DbContextOptions<ClinicBookingDbContext>) ||
                d.ServiceType == typeof(IDbContextOptionsConfiguration<ClinicBookingDbContext>)).ToList();
            foreach (var d in toRemove)
                services.Remove(d);

            var dbName = $"bola-tests-{Guid.NewGuid():N}";
            services.AddDbContext<ClinicBookingDbContext>(
                opt => opt.UseInMemoryDatabase(dbName));
        });
    }

    /// <summary>Insère un rendez-vous de démonstration et retourne (patientId, appointmentId).</summary>
    public async Task<(string PatientId, Guid AppointmentId)> SeedAsync()
    {
        if (_seededAppointmentId != Guid.Empty)
            return (_seededPatientId, _seededAppointmentId);

        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ClinicBookingDbContext>();
        await db.Database.EnsureCreatedAsync();

        var patientId = "demo-patient-a-" + Guid.NewGuid().ToString("N");
        var appointment = new Appointment
        {
            Id = Guid.NewGuid(),
            PatientId = patientId,
            DoctorId = "demo-doctor-" + Guid.NewGuid().ToString("N"),
            ScheduledAt = DateTimeOffset.UtcNow.AddDays(1),
            Status = AppointmentStatus.Scheduled,
        };
        db.Appointments.Add(appointment);
        await db.SaveChangesAsync();

        _seededPatientId = patientId;
        _seededAppointmentId = appointment.Id;
        return (_seededPatientId, _seededAppointmentId);
    }

    /// <summary>Crée un client HTTP avec un JWT signé pour l'utilisateur donné.</summary>
    public HttpClient CreateAuthenticatedClient(string userId, string role)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(TestKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(
            issuer: "ClinicBooking.Tests",
            audience: "ClinicBooking.Tests",
            claims: [
                new Claim(ClaimTypes.NameIdentifier, userId),
                new Claim(ClaimTypes.Role, role),
                new Claim("role", role),
            ],
            expires: DateTime.UtcNow.AddMinutes(15),
            signingCredentials: creds);

        var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
        var client = CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", tokenString);
        return client;
    }
}
