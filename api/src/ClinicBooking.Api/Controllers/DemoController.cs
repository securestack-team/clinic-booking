// DEMO UNIQUEMENT — Ce contrôleur introduit volontairement des vulnérabilités pour
// démontrer la détection par la pipeline DevSecOps.
// Il ne doit JAMAIS être mergé dans main.
//
// Vulnérabilités introduites :
//   - Vuln 2 : Injection SQL via FromSqlRaw concaténé (CWE-89) → détectée par CodeQL / Semgrep
//   - Vuln 4 : BOLA — accès à un rendez-vous sans vérifier que l'appelant en est propriétaire
//              (CWE-639 / OWASP API Security Top 10 : API1:2023) → détectée par test de sécurité

using ClinicBooking.Api.Data;
using ClinicBooking.Api.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace ClinicBooking.Api.Controllers;

[ApiController]
[Route("api/demo")]
public sealed class DemoController(ClinicBookingDbContext db) : ControllerBase
{
    // -------------------------------------------------------------------------
    // Vuln 2 : Injection SQL
    // La valeur de `name` vient directement de la requête HTTP et est concaténée
    // dans la chaîne SQL. Un attaquant peut injecter une sous-requête arbitraire.
    // CodeQL (cs/sql-injection) et Semgrep détectent ce flux de données non fiables.
    // -------------------------------------------------------------------------

    /// <summary>
    /// [DEMO — VULNÉRABLE] Recherche de rendez-vous par nom.
    /// Vulnérable à l'injection SQL via concaténation.
    /// </summary>
    [HttpGet("search")]
    [Authorize]
    public async Task<IActionResult> Search([FromQuery] string name)
    {
        // INTENTIONNELLEMENT VULNÉRABLE : ne jamais faire ça en production.
        var sql = "SELECT * FROM \"Appointments\" WHERE \"PatientId\" LIKE '%" + name + "%'";
        var results = await db.Appointments
            .FromSqlRaw(sql)
            .ToListAsync();
        return Ok(results);
    }

    // -------------------------------------------------------------------------
    // Vuln 4 : BOLA (Broken Object Level Authorization)
    // L'endpoint retourne le rendez-vous pour l'ID demandé sans vérifier que
    // l'utilisateur connecté en est le propriétaire. Tout utilisateur authentifié
    // peut accéder au rendez-vous d'un autre en connaissant son identifiant.
    // -------------------------------------------------------------------------

    /// <summary>
    /// [DEMO — VULNÉRABLE] Récupère un rendez-vous par ID sans contrôle de propriété.
    /// Vulnérable au BOLA : n'importe quel utilisateur authentifié peut lire
    /// le rendez-vous d'un autre.
    /// </summary>
    [HttpGet("appointments/{id:guid}")]
    [Authorize]
    public async Task<IActionResult> GetAppointment(Guid id)
    {
        // INTENTIONNELLEMENT VULNÉRABLE : aucun contrôle que l'appelant est
        // bien le propriétaire du rendez-vous. Un patient peut lire les
        // rendez-vous d'un autre en énumérant les identifiants.
        var appointment = await db.Appointments.FindAsync(id);
        if (appointment is null)
        {
            return NotFound();
        }
        // Correction attendue (non implémentée ici par conception) :
        //   var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        //   if (appointment.PatientId != userId) return Forbid();
        return Ok(appointment);
    }
}
