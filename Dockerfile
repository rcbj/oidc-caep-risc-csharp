# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
# `docker build --target test .` runs the suite in this image: the .NET tests, then the Python tests of
# the install script's trust-chain step. The demo image below does not run it.
#
# The iya-sts listener CA trust chain is the one thing from demo/generated the demo image carries.
# scripts/configure_iya_sts.py writes it to the file demo/oidc.json's tlsCa names
# (demo/generated/idp-ca.pem), and `COPY demo demo` in the last stage takes it in, because .dockerignore
# admits that file and nothing else under demo/generated (the client secret stays out, and is mounted).
# A build before the install script has run (CI, a fresh clone) has no chain file and still succeeds:
# the same directory COPY simply finds none. Rebuild after running the install script against another
# iya-sts.
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS test
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
ENV DOTNET_NOLOGO=1
RUN apt-get update && apt-get install -y --no-install-recommends python3 openssl && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN dotnet test --nologo && python3 -m unittest discover -s scripts -p 'test_*.py' -v

# The compile step sees only the sources, so a new trust chain or demo/oidc.json rebuilds no binary.
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
ENV DOTNET_NOLOGO=1
WORKDIR /src
COPY src src
COPY demo/OidcCaepRisc.Demo.csproj demo/Program.cs demo/
RUN dotnet publish demo/OidcCaepRisc.Demo.csproj -c Release -o /out --nologo -p:UseAppHost=false

# The runtime without the demo: python3 and openssl for the scripts (trust_chain.py reads certificate
# names with openssl).
FROM mcr.microsoft.com/dotnet/runtime:8.0 AS tools
RUN apt-get update && apt-get install -y --no-install-recommends python3 openssl curl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY scripts scripts

FROM tools
COPY --from=build /out /app
COPY LICENSE README.md VERSION ./
COPY demo/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
COPY demo demo
ENV PORT=3000
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s \
  CMD curl -fsS "http://127.0.0.1:$PORT/healthz" || exit 1
# At start the chain is refreshed from iya-sts into the tlsCa file, keeping the built-in one when that
# fails. TLS_CA_REFRESH=0 turns the refresh off, so the chain is the one the image was built with.
ENV TLS_CA_REFRESH=1
ENTRYPOINT ["/entrypoint.sh"]
CMD ["dotnet", "/app/oidc-caep-risc-demo.dll"]
