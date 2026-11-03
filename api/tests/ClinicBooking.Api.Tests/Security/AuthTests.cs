using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Xunit;

namespace ClinicBooking.Api.Tests.Security;

/// <summary>
/// Inscription et connexion JWT : parcours complet et cas refusés.
/// </summary>
public sealed class AuthTests : IClassFixture<AuthTestApplicationFactory>
{
    private const string StrongPassword = "Str0ng!Passw0rd";
    private readonly AuthTestApplicationFactory _factory;

    public AuthTests(AuthTestApplicationFactory factory)
    {
        _factory = factory;
    }

    private static string NewEmail() => $"patient-{Guid.NewGuid():N}@example.com";

    private static Task<HttpResponseMessage> PostAsync(HttpClient client, string path, string email, string password) =>
        client.PostAsJsonAsync(path, new { email, password });

    [Fact]
    public async Task Register_ThenLogin_ReturnsSignedPatientToken()
    {
        using var client = _factory.CreateClient();
        var email = NewEmail();

        using var register = await PostAsync(client, "/api/auth/register", email, StrongPassword);
        Assert.Equal(HttpStatusCode.OK, register.StatusCode);

        using var login = await PostAsync(client, "/api/auth/login", email, StrongPassword);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);

        var body = await login.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("Patient", body.GetProperty("role").GetString());

        var token = new JwtSecurityTokenHandler().ReadJwtToken(body.GetProperty("accessToken").GetString());
        Assert.Equal("ClinicBooking.Tests", token.Issuer);
        Assert.Contains(token.Claims, c => c.Type is ClaimTypes.Role or "role" && c.Value == "Patient");
        Assert.True(token.ValidTo <= DateTime.UtcNow.AddMinutes(16), "Le token doit être de courte durée.");
    }

    // Menace : comptes faciles à deviner. Contrôle : politique de mot de passe d'Identity.
    [Theory]
    [InlineData("short")]
    [InlineData("alllowercase123!")]
    [InlineData("NoDigitsHere!!")]
    public async Task Register_WithWeakPassword_IsRejected(string password)
    {
        using var client = _factory.CreateClient();
        using var response = await PostAsync(client, "/api/auth/register", NewEmail(), password);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Register_SameEmailTwice_IsRejected()
    {
        using var client = _factory.CreateClient();
        var email = NewEmail();
        using var first = await PostAsync(client, "/api/auth/register", email, StrongPassword);
        using var second = await PostAsync(client, "/api/auth/register", email, StrongPassword);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, second.StatusCode);
    }

    // Menace : énumération des comptes. Contrôle : même réponse 401 pour un e-mail inconnu
    // et pour un mauvais mot de passe.
    [Fact]
    public async Task Login_WrongPasswordAndUnknownEmail_LookTheSame()
    {
        using var client = _factory.CreateClient();
        var email = NewEmail();
        using var register = await PostAsync(client, "/api/auth/register", email, StrongPassword);

        using var wrongPassword = await PostAsync(client, "/api/auth/login", email, "Wr0ng!Passw0rd");
        using var unknownEmail = await PostAsync(client, "/api/auth/login", NewEmail(), StrongPassword);

        Assert.Equal(HttpStatusCode.Unauthorized, wrongPassword.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, unknownEmail.StatusCode);
        Assert.Equal(await wrongPassword.Content.ReadAsStringAsync(), await unknownEmail.Content.ReadAsStringAsync());
    }
}
