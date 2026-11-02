# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY src src
COPY demo demo
RUN dotnet publish demo/OidcCaepRisc.Demo.csproj -c Release -o /out --nologo -p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/runtime:8.0
RUN apt-get update && apt-get install -y --no-install-recommends python3 openssl curl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /out /app
COPY demo demo
COPY scripts scripts
COPY LICENSE README.md VERSION ./
COPY demo/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
ENV PORT=3000
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s \
  CMD curl -fsS "http://127.0.0.1:$$PORT/healthz" || exit 1
ENTRYPOINT ["/entrypoint.sh"]
CMD ["dotnet", "/app/oidc-caep-risc-demo.dll"]
