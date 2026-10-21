using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace ClinicBooking.Api.Tests.Security;

/// <summary>
/// Tests de sécurité qui ne dépendent pas encore de l'authentification :
/// hôtes autorisés, erreurs sans détail interne, HSTS et CORS.
/// Les tests 401 / 403 / 400 viendront avec le login JWT.
/// </summary>
public sealed class BaselineSecurityTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string BoomPath = "/__test/boom";
    private const string InternalDetail = "detail-interne-qui-ne-doit-pas-sortir";

    private readonly WebApplicationFactory<Program> _factory;

    public BaselineSecurityTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
    }

    // Menace : en-tête Host falsifié (liens de réinitialisation empoisonnés, cache).
    // Contrôle : AllowedHosts. Seuls les hôtes configurés sont servis.
    [Fact]
    public async Task UnknownHost_IsRejected()
    {
        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("http://evil.example"),
        });
        using var response = await client.GetAsync("/api/ping");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Theory]
    [InlineData("http://localhost")]
    [InlineData("http://127.0.0.1")]
    public async Task AllowedHost_IsServed(string baseAddress)
    {
        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(baseAddress),
        });
        using var response = await client.GetAsync("/api/ping");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // AllowedHosts doit pouvoir venir de la configuration (variable d'environnement
    // AllowedHosts sur Azure), sinon l'API refusera son propre nom de domaine.
    [Fact]
    public async Task AllowedHosts_FromConfiguration_IsApplied()
    {
        using var factory = _factory.WithWebHostBuilder(builder =>
            builder.UseSetting("AllowedHosts", "clinic.example"));

        using var allowed = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("http://clinic.example"),
        });
        using var allowedResponse = await allowed.GetAsync("/api/ping");
        Assert.Equal(HttpStatusCode.OK, allowedResponse.StatusCode);

        using var other = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("http://evil.example"),
        });
        using var otherResponse = await other.GetAsync("/api/ping");
        Assert.Equal(HttpStatusCode.BadRequest, otherResponse.StatusCode);
    }

    // Menace : une erreur non gérée renvoie la pile d'appels ou le message interne
    // (A10:2025 Mishandling of Exceptional Conditions).
    // Contrôle : UseExceptionHandler + ProblemDetails, sans détail en production.
    [Fact]
    public async Task UnhandledError_InProduction_ReturnsProblemDetailsWithoutInternals()
    {
        using var factory = _factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.ConfigureServices(services =>
                services.AddSingleton<IStartupFilter, ThrowingEndpointStartupFilter>());
        });
        using var client = factory.CreateClient();
        using var response = await client.GetAsync(BoomPath);
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.DoesNotContain(InternalDetail, body);
        Assert.DoesNotContain(nameof(InvalidOperationException), body);
        Assert.DoesNotContain("StackTrace", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(".cs:line", body);
    }

    [Fact]
    public async Task UnknownRoute_Returns404WithoutBody()
    {
        using var client = _factory.CreateClient();
        using var response = await client.GetAsync("/api/route-qui-n-existe-pas");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Empty(await response.Content.ReadAsStringAsync());
    }

    // Menace : un attaquant sur le réseau force le navigateur à repasser en HTTP.
    // Contrôle : HSTS hors développement.
    [Fact]
    public async Task Https_InProduction_SendsHsts()
    {
        using var factory = _factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            // HSTS ne s'applique jamais à localhost : on simule le vrai nom de domaine.
            builder.UseSetting("AllowedHosts", "clinic.example");
        });
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://clinic.example"),
        });
        using var response = await client.GetAsync("/api/ping");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.Contains("Strict-Transport-Security"));
    }

    // Menace : un site tiers appelle l'API depuis le navigateur d'un patient connecté.
    // Contrôle : CORS limité au site web. Un autre site ne doit jamais être autorisé.
    [Fact]
    public async Task CrossOriginRequest_FromUnknownSite_IsNotAllowed()
    {
        using var client = _factory.CreateClient();

        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/ping");
        request.Headers.Add("Origin", "https://evil.example");
        using var response = await client.SendAsync(request);
        Assert.False(response.Headers.Contains("Access-Control-Allow-Origin"));

        using var preflight = new HttpRequestMessage(HttpMethod.Options, "/api/ping");
        preflight.Headers.Add("Origin", "https://evil.example");
        preflight.Headers.Add("Access-Control-Request-Method", "DELETE");
        using var preflightResponse = await client.SendAsync(preflight);
        Assert.False(preflightResponse.Headers.Contains("Access-Control-Allow-Origin"));
    }

    /// <summary>
    /// Ajoute, pour ce test seulement, une route qui lève une exception. Elle est placée
    /// après le pipeline de l'API, donc à l'intérieur de son UseExceptionHandler.
    /// </summary>
    private sealed class ThrowingEndpointStartupFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            next(app);
            app.Use((HttpContext context, RequestDelegate nextMiddleware) =>
                context.Request.Path == BoomPath
                    ? throw new InvalidOperationException(InternalDetail)
                    : nextMiddleware(context));
        };
    }
}
