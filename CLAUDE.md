# oidc-caep-risc-csharp

A confidential OpenID Connect relying party for a traditional .NET application, and a CAEP and RISC receiver on one Shared Signals poll stream. Authorization Code with PKCE (S256) is required. Client authentication is `client_secret_basic`, `client_secret_post`, or `private_key_jwt`. A public client (`none`) is refused.

`signals` defaults to on. `signals: false` turns CAEP and RISC off: the receiver does not start, transmitter metadata is not required, and the authorization request does not include `ssf.read` or `ssf.manage`. `DEFAULT_SCOPES` still names those two scopes. They are removed after that default is applied. The shipped demo omits `signals`, so they stay on.

The license is the MIT License in `LICENSE`. A pull request merged into `main` publishes the package to nuget.org after the test workflow succeeds on that commit. A direct push does not. The key comes from nuget.org Trusted Publishing (`NuGet/login` trades the workflow's GitHub OIDC token for a one-hour API key); the `NUGET_USER` repository secret is the nuget.org profile name that owns the policy for this repository and `publish.yml`. A version already on nuget.org stays there; the next release is a new `Version` in the library's `.csproj`. `develop` and `main` are the branches the test workflow runs.

.NET 8. Cryptography is the base class library: RSA PKCS#1, RSA-PSS, and ECDSA P-1363. EdDSA and Ed25519 are not verified. Mutual-TLS client certificates are not sent.

## Layout

| Path | What it is |
|---|---|
| namespace `IyaSec.Oidc` | The library. `FromFile`, `Authorize`, `Complete`. Package `IyaSec.OidcCaepRisc`. |
| `tests/IyaSec.OidcCaepRisc.Tests` | `dotnet test`. A stub provider and a stub transmitter. No live iya-sts. `TlsTrustTests` runs a leaf-only HTTPS listener against `tlsCa`: a certificate that chains to it but names another host is refused (`Http.Accept`; an IP literal needs an IP SAN). Every PEM block of the file is read (`Http.LoadPem`), and a forged leaf sent with the real CA certificates is refused: there is no pin shortcut. `ClientProfileTests` covers issue #30 (DPoP, acr, required PAR, the algorithm allow-list, required `typ`/`at_hash`, `Create` defaults and the redirect rule, the session token cache); the stubs check each DPoP proof with `DpopProof`, written apart from the library's signer. `DpopSignalsTests` requires a proof on every transmitter call. |
| `demo` | `demo/Program.cs` and `demo/public/`. Config is `demo/oidc.json`. |
| `scripts` | `configure_iya_sts.py` registers the confidential client. `trust_chain.py` refreshes the listener CA file named by `tlsCa`. `live_iya_sts.py` is the live sign-in, separate from the unit suite. |
| `Dockerfile`, `docker-compose.yml` | The demo image. Compose uses host networking. |

## Usage

```csharp
var rp = IyaSec.Oidc.RelyingParty.FromFile("oidc.json");
var request = rp.Authorize();
var who = rp.Complete(query, request);
```

Keep the transaction (`State`, nonce, code verifier, `AcrValues`) until the browser returns. Tokens stay in this process.

## Client profile settings

These defaults apply whether the configuration is read from a file (`RelyingParty.FromFile`, `Config.ResolveConfig`) or built in code and given to `RelyingParty.Create` (`Config.ApplyDefaults` is the one place they are set).

| Setting | Default | Meaning |
|---|---|---|
| `par` | `auto` | `auto` pushes the authorization request when the provider has a PAR endpoint, `always` requires one (creation fails without it), `never` does not push. When discovery says `require_pushed_authorization_requests: true`, `never` fails at creation and `auto` always pushes. |
| `dpop` | `auto` | DPoP (RFC 9449). `auto` uses it when the provider's `dpop_signing_alg_values_supported` lists ES256; `always` fails at creation otherwise; `never` sends no proofs. |
| `dpopKey` | none | A PEM P-256 private key (inline, `file:`, `env:`, or a path) for the DPoP proofs, for an application that runs several processes. Without it the key pair is generated when the relying party is created and held in memory only. |
| `idTokenSigningAlgs` | `["RS256"]` | The ID token algorithms accepted, intersected with the provider's `id_token_signing_alg_values_supported`; creation fails when the intersection is empty. `none` is never accepted. A symmetric algorithm (HS256, HS384, HS512) is accepted only when named here. |
| `idTokenSignedResponseAlg` | none | Pins one algorithm; the provider must advertise it. |
| `requireIdTokenTypAndAtHash` | `true` | The ID token header must carry `typ` `JWT` or `application/jwt`, and when the token response carries an access token the ID token must carry a matching `at_hash`. `false` checks each only when present. |
| `acrValues` | none | `acr_values` (a string or a list) sent on every authorization request; `AuthorizeOptions.AcrValues` overrides it per request. When `acr_values` was sent, the code exchange's ID token must carry an `acr` that is one of them. The refresh path does not re-check `acr`. |
| `clockToleranceSec` | 30 | Clock skew for `exp`, `nbf`, `iat`, and `auth_time`. An `iat` more than this in the future is refused. |
| `maxIdTokenAgeSec` | 600 | The oldest `iat` accepted. |

`redirectUri`, `postLogoutRedirectUri`, and a per-request `AuthorizeOptions.RedirectUri` must be https, or http on a loopback host (`localhost`, `127.0.0.1`, `[::1]`). `allowInsecure` does not relax this; it only lets the provider's own endpoints use http.

### DPoP

When DPoP is in use, a proof (`typ` `dpop+jwt`, the public `jwk`, `jti`, `htm`, `htu` without query or fragment, `iat`) goes on every PAR request and every token request (code, refresh, client credentials), and `dpop_jkt` (the key's RFC 7638 thumbprint) goes on the authorization request (in the PAR body when PAR is used). The token response's `token_type` must then be `DPoP`; without a proof it must be `Bearer`. A 400 `use_dpop_nonce` from the authorization server, or a 401 with `WWW-Authenticate: DPoP error="use_dpop_nonce"` from a resource server, is retried once with the nonce the response gave, and the latest nonce per origin is sent on the next proof.

`rp.ResourceRequest(method, url, headers, body, accessToken)` calls a resource server with the token: `Authorization: DPoP` and a proof carrying `ath` when DPoP is in use, `Authorization: Bearer` otherwise. `rp.UserInfo` uses it. `SignalsReceiver.New(...).WithRelyingParty(rp)` calls the SSF transmitter with the relying party's client-credentials token for `ssf.manage` through the same path, so every transmitter call carries a proof when the token is DPoP-bound. `rp.UsesDpop` and `rp.DpopSigner` say whether and with which key.

### Session token cache

`rp.Complete(query, request, sessionId)` keeps the sign-in's tokens in `rp.SessionStore` under `sessionId`, or under a new handle when none is given (`login.SessionId` either way). `rp.SessionAccessToken(sessionId)` returns a valid access token: the cached one while it has more than 30 seconds left, otherwise one obtained with the refresh token (with a DPoP proof when DPoP is in use), and the cache is updated. An unknown session, an expired one with no refresh token, or a failed refresh removes the entry and throws `OidcError` with code `session`. `rp.RemoveSession(sessionId)` clears an entry; a receiver built `WithRelyingParty(rp)` also clears the entries of sessions it ends (a CAEP `session-revoked`) and of `Untrack`. The default store is `MemorySessionTokenStore`; set `rp.SessionStore` to an `ISessionTokenStore` of your own for a store shared across processes.

## The iya-sts trust chain (`tlsCa`)

`tlsCa` in `demo/oidc.json` (default `generated/idp-ca.pem`, relative to `demo/`) names the iya-sts TLS listener CA trust chain. The install script, `python3 scripts/configure_iya_sts.py`, fetches the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root; the chain the handshake presents when that is missing), writes it to that file, and prints the path, the anchor's subject and its SHA-256. The library reads every PEM block of the file as its trust store.

The demo image carries that file from build time: `COPY demo demo` takes it in, and `.dockerignore` admits it and nothing else under `demo/generated` (the client secret and a generated test-user password stay out). Build the demo image after the install script has run, and rebuild it after re-running the install script against a different iya-sts. A build without the file (CI, a fresh clone) still succeeds. At start the container refreshes the file from iya-sts and keeps the built-in one when that fails; `TLS_CA_REFRESH=0` turns the refresh off.

The install script never prints a generated test-user password: it writes it to `demo/generated/<user>.password` (mode 0600) and prints only that path. The client secret is `demo/generated/client-secret` (mode 0600), mounted into the demo container, never built into the image; it is never printed, and `--dry-run`'s plan does not hold it.

## Tests

```bash
docker build --target test .
```

The `test` stage runs `dotnet test --nologo` in `mcr.microsoft.com/dotnet/sdk:8.0`, then `python3 -m unittest discover -s scripts -p 'test_*.py'` (`scripts/test_trust_chain.py`: the install script writes the whole chain to the `tlsCa` file; `scripts/test_password_file.py`: a generated password goes to a 0600 file and is never printed, and the plan never holds the client secret). GitHub Actions uses that command. Do not run the .NET SDK on the host. The demo image does not run the suite.

The stub tests do not start iya-sts. `python3 scripts/live_iya_sts.py` does, unless `IYA_STS_URL` names one that is already running. It starts iya-sts when `IYA_STS_URL` is unset, runs the install script in a copy of the repository (which writes the client secret and the trust chain into that copy's `demo/generated`), then builds the demo image, checks that the image holds the saved chain and no client secret, and runs it with only the client secret mounted and `TLS_CA_REFRESH=0`. It then signs in, and requires a credential-change event and a session-revoked event on `GET /live-status`. The second event ends the local session. The nightly workflow runs the unit suite and this script. `.github/workflows/nightly.yml` runs at 07:34 UTC (`34 7 * * *`) and on `workflow_dispatch`. `IYA_STS_IMAGE` starts a fresh container from an image already built; without it or `IYA_STS_URL` the script clones and builds iya-sts `main`. `LIVE_STS_PORT` defaults to 18524 and `LIVE_DEMO_PORT` to 18624; the script refuses 3000, 8081, and 18481 through 18495. Registration runs `scripts/configure_iya_sts.py` with the host's stdlib python3, never dotnet. Always use a fresh iya-sts: a second registration of the same client fails. The Dockerfile health check reads `$PORT`; it read `$$PORT`, which the shell expands to its own PID.

## Demo

`docker-compose.yml` sets `network_mode: host`. The process binds `PORT`, default 3000. `ENV PORT=3000` in the image keeps an unset value on 3000, and the health check calls `http://127.0.0.1:${PORT}/healthz`.

```sh
docker compose up --build
```

`GET /healthz` returns `ok`. `GET /` is the page. `GET /login` redirects to the provider. `GET /callback` completes the sign-in. `POST /logout` ends the local session. `GET /live-status` is JSON for the sign-in and the Shared Signals events this process has accepted. It does not include tokens. It also says whether the relying party uses DPoP (`dpop`). The demo's local session id is the key of the library's session token cache: `/callback` passes it to `Complete`, `GET /` calls `SessionAccessToken` and then `UserInfo` with that token (a `session` refusal ends the local session), sign-out calls `RemoveSession`, and the receiver is built `WithRelyingParty`, so its transmitter calls are DPoP-aware. `scripts/configure_iya_sts.py` registers the client with `oauthIdTokenSignedResponseAlg: RS256` (iya-sts's name for `id_token_signed_response_alg`). The demo and the test stub provider pick handlers from a table keyed by method and path, not an if-chain on the request (CodeQL cs/user-controlled-bypass). A page never shows an exception message: the demo logs it and the page says the reason is in the log; a refused sign-in shows only the library error code (CodeQL cs/information-exposure-through-exception).

A loopback redirect follows `PORT` in the running server and in `scripts/configure_iya_sts.py`. Any other host is left as written. An explicit `--public-url` or a non-empty `PUBLIC_URL` replaces the origin and keeps the path. The running container's `PORT` wins over the shell's when the script registers the application. `pollIntervalMs` is a millisecond pause, not a port.

Open `http://127.0.0.1:$PORT` after the provider is up. Do not bind port 3000 or 8081 while another demo or iya-sts is already using them.
