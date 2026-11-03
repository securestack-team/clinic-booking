# Image de l'API : build avec le SDK, exécution sur une image minimale sans shell et non-root.

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY src/ClinicBooking.Api/ClinicBooking.Api.csproj src/ClinicBooking.Api/
RUN dotnet restore src/ClinicBooking.Api/ClinicBooking.Api.csproj
COPY src/ src/
RUN dotnet publish src/ClinicBooking.Api/ClinicBooking.Api.csproj \
    --configuration Release --no-restore --output /app/publish /p:UseAppHost=false

# "chiseled" : pas de shell ni de gestionnaire de paquets, utilisateur non-root par défaut.
FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled AS runtime
WORKDIR /app
COPY --from=build /app/publish .
USER $APP_UID
ENV ASPNETCORE_HTTP_PORTS=8080 \
    DOTNET_EnableDiagnostics=0
EXPOSE 8080
ENTRYPOINT ["dotnet", "ClinicBooking.Api.dll"]
