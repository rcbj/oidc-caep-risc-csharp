# oidc-caep-risc-csharp

A confidential OpenID Connect relying party for a traditional .NET application, and a CAEP and RISC receiver on one Shared Signals poll stream. Authorization Code with PKCE (S256) is required. Client authentication is `client_secret_basic`, `client_secret_post`, or `private_key_jwt`. A public client (`tokenEndpointAuthMethod` `"none"`) is refused. The library uses the .NET base class library for HTTP, JSON, RSA (PKCS#1 and PSS), ECDSA (P-1363), and HMAC. EdDSA and Ed25519 are named where a provider advertises them and are not verified in this runtime.

JSON configuration keys match the Python library `oidc-caep-risc`. `signals` omitted or `true` keeps CAEP and RISC on. `signals: false` does not start the receiver, does not require transmitter metadata, and drops `ssf.read` and `ssf.manage` from the scope list after the default scopes are applied. `DEFAULT_SCOPES` still names those two scopes. The shipped demo leaves `signals` on (the key is omitted).

The license is MIT. Package id: `IyaSec.OidcCaepRisc`. A pull request merged into `main` publishes the package to nuget.org after the test workflow succeeds on that commit. A direct push does not. The key comes from nuget.org Trusted Publishing (`NuGet/login` trades the workflow's GitHub OIDC token for a one-hour API key); the `NUGET_USER` repository secret is the nuget.org profile name that owns the policy for this repository and `publish.yml`. A version already on nuget.org stays there; the next release is a new `Version` in the library's `.csproj`.

## Usage

```bash
dotnet add package IyaSec.OidcCaepRisc
```

```csharp
var rp = IyaSec.Oidc.RelyingParty.FromFile("oidc.json");
var request = rp.Authorize();
// redirect the browser to request.Url; keep State, Nonce, and CodeVerifier
var who = rp.Complete(query, request);
```

Tokens stay in this process. Keep the transaction until the browser returns.

`tlsCa` names the iya-sts TLS listener CA trust chain for every back-channel request. A certificate the platform already trusts, or one that chains to `tlsCa`, is accepted only when it names the host in the URL: a DNS name must match a DNS SAN and an IP literal such as `127.0.0.1` an IP address SAN. A certificate that chains to `tlsCa` but names another host is refused.

## The iya-sts trust chain (`tlsCa`)

`tlsCa` in `demo/oidc.json` (default `generated/idp-ca.pem`, relative to `demo/`) names the iya-sts TLS listener CA trust chain. The install script, `python3 scripts/configure_iya_sts.py`, fetches the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root; the chain the handshake presents when that is missing), writes it to that file, and prints the path, the anchor's subject and its SHA-256. The library reads every PEM block of the file as its trust store.

The demo image carries that file from build time: `COPY demo demo` takes it in, and `.dockerignore` admits it and nothing else under `demo/generated` (the client secret and a generated test-user password stay out). Build the demo image after the install script has run, and rebuild it after re-running the install script against a different iya-sts. A build without the file (CI, a fresh clone) still succeeds. At start the container refreshes the file from iya-sts and keeps the built-in one when that fails; `TLS_CA_REFRESH=0` turns the refresh off.

The install script never prints a generated test-user password: it writes it to `demo/generated/<user>.password` (mode 0600) and prints only that path. The client secret is `demo/generated/client-secret` (mode 0600), mounted into the demo container, never built into the image; it is never printed, and `--dry-run`'s plan does not hold it.

## Tests

```bash
docker build --target test .
```

The suite runs in a container.

The tests build an in-process stub provider and a stub transmitter. They do not need a live iya-sts.

`python3 scripts/live_iya_sts.py` is the live half. It starts iya-sts when `IYA_STS_URL` is unset, runs the install script in a copy of the repository (which writes the client secret and the trust chain into that copy's `demo/generated`), then builds the demo image, checks that the image holds the saved chain and no client secret, and runs it with only the client secret mounted and `TLS_CA_REFRESH=0`. It then signs in, and requires a credential-change event and a session-revoked event on `GET /live-status`. The second event ends the local session. The nightly workflow runs the unit suite and this script. `.github/workflows/nightly.yml` runs at 07:34 UTC (`34 7 * * *`) and on `workflow_dispatch`. `IYA_STS_IMAGE` starts a fresh container from an image already built; without it or `IYA_STS_URL` the script clones and builds iya-sts `main`. `LIVE_STS_PORT` defaults to 18524 and `LIVE_DEMO_PORT` to 18624; the script refuses 3000, 8081, and 18481 through 18495. Registration runs `scripts/configure_iya_sts.py` with the host's stdlib python3, never dotnet. Always use a fresh iya-sts: a second registration of the same client fails.

## Layout

| Path | What it is |
|---|---|
| `src/IyaSec.OidcCaepRisc` | The library, package `IyaSec.OidcCaepRisc`, namespace `IyaSec.Oidc`. |
| `tests/IyaSec.OidcCaepRisc.Tests` | `dotnet test` ports of the Python relying-party and Shared Signals tests. |
| `demo` | `demo/Program.cs`. Config is `demo/oidc.json`. |
| `scripts/configure_iya_sts.py` | Registers the confidential client on iya-sts. Loopback redirects follow the running container's `PORT`, then the shell `PORT`. |
| `scripts/live_iya_sts.py` | The live sign-in against iya-sts, separate from the unit suite. |
| `Dockerfile`, `docker-compose.yml` | The demo image. Compose uses host networking. |

## Demo

`PORT` defaults to 3000. A loopback redirect and post-logout URL follow `PORT`. Any other host is left as written. An explicit `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. The default `http://localhost:3000` is not an explicit public URL.

```sh
docker compose up --build
```

`GET /healthz` returns `ok`. `GET /` is the page. `GET /login` starts `Authorize` and redirects. `GET /callback` completes the code exchange. `POST /logout` signs the local session out. `GET /live-status` is JSON for the sign-in and the Shared Signals events this process has accepted. It does not include tokens.

`docker-compose.yml` sets `network_mode: host`. The image sets `ENV PORT=3000`. The health check calls `http://127.0.0.1:${PORT}/healthz`. The running container's `PORT` wins over the shell's when `scripts/configure_iya_sts.py` registers the application.

Demo JSON uses `file:` and the configuration's own placeholders. It does not contain a generated secret or key.
