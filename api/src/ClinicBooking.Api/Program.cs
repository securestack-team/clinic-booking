using ClinicBooking.Api;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddHealthChecks();
builder.Services.AddProblemDetails();

if (builder.Environment.IsDevelopment())
{
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen();
}

var app = builder.Build();

app.UseExceptionHandler();

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

app.Run();

// Rend le point d'entrée accessible aux tests d'intégration.
public partial class Program { }
