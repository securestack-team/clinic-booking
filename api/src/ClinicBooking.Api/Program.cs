using System.Text;
using ClinicBooking.Api;
using ClinicBooking.Api.Auth;
using ClinicBooking.Api.Data;
using ClinicBooking.Api.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

var connectionString = builder.Configuration.GetConnectionString("Default");
if (string.IsNullOrWhiteSpace(connectionString))
{
    throw new InvalidOperationException(
        "La chaîne de connexion 'ConnectionStrings:Default' est requise.");
}

builder.Services.AddDbContext<ClinicBookingDbContext>(options =>
    options.UseNpgsql(connectionString));
builder.Services.AddIdentityCore<ApplicationUser>(options =>
    {
        options.User.RequireUniqueEmail = true;
        options.Password.RequiredLength = 12;
        options.Password.RequireDigit = true;
        options.Password.RequireUppercase = true;
        options.Password.RequireLowercase = true;
        options.Password.RequireNonAlphanumeric = true;
    })
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<ClinicBookingDbContext>()
    .AddSignInManager();

var jwtOptions = builder.Configuration.GetSection(JwtOptions.SectionName).Get<JwtOptions>()
    ?? throw new InvalidOperationException("La configuration JWT est requise.");
if (string.IsNullOrWhiteSpace(jwtOptions.Key) || Encoding.UTF8.GetByteCount(jwtOptions.Key) < 32)
{
    throw new InvalidOperationException("La clé JWT doit contenir au moins 32 octets.");
}
if (string.IsNullOrWhiteSpace(jwtOptions.Issuer) || string.IsNullOrWhiteSpace(jwtOptions.Audience))
{
    throw new InvalidOperationException("L'émetteur et l'audience JWT sont requis.");
}

builder.Services.AddSingleton<IOptions<JwtOptions>>(Options.Create(jwtOptions));
builder.Services.AddSingleton<JwtTokenService>();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.Key)),
            ValidateIssuer = true,
            ValidIssuer = jwtOptions.Issuer,
            ValidateAudience = true,
            ValidAudience = jwtOptions.Audience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30)
        };
    });
builder.Services.AddAuthorization();
builder.Services.AddHealthChecks();
builder.Services.AddProblemDetails();

if (builder.Environment.IsDevelopment())
{
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen();
}

var app = builder.Build();

app.UseExceptionHandler();
app.UseAuthentication();
app.UseAuthorization();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
else
{
    app.UseHsts();
}

app.MapHealthChecks("/health");
app.MapGet("/api/ping", () => TypedResults.Ok(new PingResponse("pong")))
    .WithName("Ping")
    .WithSummary("Vérifie que l'API répond.");

app.MapPost("/api/auth/register", async (
    RegisterRequest request,
    UserManager<ApplicationUser> userManager,
    RoleManager<IdentityRole> roleManager,
    JwtTokenService tokenService) =>
{
    if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
    {
        return Results.BadRequest(new { message = "L'adresse e-mail et le mot de passe sont requis." });
    }

    var email = request.Email.Trim().ToLowerInvariant();
    var user = new ApplicationUser { UserName = email, Email = email };
    var result = await userManager.CreateAsync(user, request.Password);
    if (!result.Succeeded)
    {
        return Results.BadRequest(new
        {
            message = "Les données d'inscription sont invalides.",
            errors = result.Errors.Select(error => error.Code)
        });
    }

    const string role = AuthRoles.Patient;
    if (!await roleManager.RoleExistsAsync(role))
    {
        await roleManager.CreateAsync(new IdentityRole(role));
    }

    var roleResult = await userManager.AddToRoleAsync(user, role);
    if (!roleResult.Succeeded)
    {
        await userManager.DeleteAsync(user);
        return Results.Problem("Impossible d'attribuer le rôle utilisateur.");
    }

    return Results.Ok(tokenService.CreateToken(user, role));
})
    .WithName("Register")
    .WithSummary("Crée un compte patient et retourne un access token.");

app.MapPost("/api/auth/login", async (
    LoginRequest request,
    UserManager<ApplicationUser> userManager,
    JwtTokenService tokenService) =>
{
    if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
    {
        return Results.Unauthorized();
    }

    var user = await userManager.FindByEmailAsync(request.Email.Trim());
    if (user is null || !await userManager.CheckPasswordAsync(user, request.Password))
    {
        return Results.Unauthorized();
    }

    var role = (await userManager.GetRolesAsync(user)).SingleOrDefault();
    if (role is null)
    {
        return Results.Problem("Le compte n'a pas de rôle valide.");
    }

    return Results.Ok(tokenService.CreateToken(user, role));
})
    .WithName("Login")
    .WithSummary("Authentifie un utilisateur et retourne un access token.");

app.Run();

// Rend le point d'entrée accessible aux tests d'intégration.
public partial class Program { }
