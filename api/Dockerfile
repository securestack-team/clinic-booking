# Image de l'API : build avec le SDK, exécution sur une image minimale sans shell et non-root.

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY src/ClinicBooking.Api/ClinicBooking.Api.csproj src/ClinicBooking.Api/
RUN dotnet restore src/ClinicBooking.Api/ClinicBooking.Api.csproj
COPY src/ src/
RUN dotnet publish src/ClinicBooking.Api/ClinicBooking.Api.csproj \
    --configuration Release --no-restore --output /app/publish /p:UseAppHost=false

# DEMO UNIQUEMENT : configuration volontairement vulnérable.
# USER root expose le conteneur en root, ce qu'Hadolint (DL3002) et Trivy détectent.
# La bonne pratique — USER $APP_UID — est intentionnellement retirée pour la démonstration.
FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled AS runtime
WORKDIR /app
COPY --from=build /app/publish .
USER root
ENV ASPNETCORE_HTTP_PORTS=8080 \
    DOTNET_EnableDiagnostics=0
EXPOSE 8080
ENTRYPOINT ["dotnet", "ClinicBooking.Api.dll"]
