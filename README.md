# oidc-caep-risc-csharp

A confidential OpenID Connect relying party for a traditional .NET application, and a CAEP and RISC receiver on one Shared Signals poll stream. Authorization Code with PKCE (S256) is required. Client authentication is `client_secret_basic`, `client_secret_post`, or `private_key_jwt`. A public client (`tokenEndpointAuthMethod` `"none"`) is refused. The library uses the .NET base class library for HTTP, JSON, RSA (PKCS#1 and PSS), ECDSA (P-1363), and HMAC. EdDSA and Ed25519 are named where a provider advertises them and are not verified in this runtime.

JSON configuration keys match the Python library `oidc-caep-risc`. `signals` omitted or `true` keeps CAEP and RISC on. `signals: false` does not start the receiver, does not require transmitter metadata, and drops `ssf.read` and `ssf.manage` from the scope list after the default scopes are applied. `DEFAULT_SCOPES` still names those two scopes. The shipped demo leaves `signals` on (the key is omitted).

The license is MIT. Publishing is not set up.

## Usage

```csharp
var rp = IyaSec.Oidc.RelyingParty.FromFile("oidc.json");
var request = rp.Authorize();
// redirect the browser to request.Url; keep State, Nonce, and CodeVerifier
var who = rp.Complete(query, request);
```

Tokens stay in this process. Keep the transaction until the browser returns.

## Tests

```sh
dotnet test
```

The tests build an in-process stub provider and a stub transmitter. They do not need a live iya-sts.

## Layout

| Path | What it is |
|---|---|
| `src/IyaSec.OidcCaepRisc` | The library, package `IyaSec.OidcCaepRisc`, namespace `IyaSec.Oidc`. |
| `tests/IyaSec.OidcCaepRisc.Tests` | `dotnet test` ports of the Python relying-party and Shared Signals tests. |
| `demo` | `demo/Program.cs`. Config is `demo/oidc.json`. |
| `scripts/configure_iya_sts.py` | Registers the confidential client on iya-sts. Loopback redirects follow the running container's `PORT`, then the shell `PORT`. |
| `Dockerfile`, `docker-compose.yml` | The demo image. Compose uses host networking. |

## Demo

`PORT` defaults to 3000. A loopback redirect and post-logout URL follow `PORT`. Any other host is left as written. An explicit `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. The default `http://localhost:3000` is not an explicit public URL.

```sh
dotnet run --project demo/OidcCaepRisc.Demo.csproj
```

`GET /healthz` returns `ok`. `GET /` is the page. `GET /login` starts `Authorize` and redirects. `GET /callback` completes the code exchange. `POST /logout` signs the local session out.

`docker-compose.yml` sets `network_mode: host`. The image sets `ENV PORT=3000`. The health check calls `http://127.0.0.1:${PORT}/healthz`. The running container's `PORT` wins over the shell's when `scripts/configure_iya_sts.py` registers the application.

Demo JSON uses `file:` and the configuration's own placeholders. It does not contain a generated secret or key.
