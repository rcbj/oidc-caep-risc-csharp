// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using IyaSec.Oidc;
using Xunit;

namespace IyaSec.OidcCaepRisc.Tests;

public sealed class ProviderFixture : IDisposable
{
    public const string Client = "oidc-caep-risc-demo";
    public const string Secret = "test-secret";
    public const string Scopes = "openid profile email offline_access ssf.read ssf.manage";
    public RSA ProviderKeys { get; } = RSA.Create(2048);
    public RSA ClientKeys { get; } = RSA.Create(2048);
    public Dictionary<string, object?> ProviderJwk { get; }
    public string ClientPem { get; }
    public Stub State { get; } = new();
    readonly HttpListener listener = new();
    readonly CancellationTokenSource stop = new();

    public ProviderFixture()
    {
        ProviderJwk = Jwk(ProviderKeys, "op");
        ClientPem = ProviderKeysExport(ClientKeys);
        var port = FreePort();
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        listener.Start();
        State.Url = $"http://127.0.0.1:{port}";
        _ = Task.Run(Accept);
    }

    public void Dispose()
    {
        stop.Cancel();
        listener.Close();
        ProviderKeys.Dispose();
        ClientKeys.Dispose();
    }

    async Task Accept()
    {
        while (!stop.IsCancellationRequested)
        {
            HttpListenerContext ctx;
            try { ctx = await listener.GetContextAsync(); }
            catch { break; }
            _ = Task.Run(() =>
            {
                try { Handle(ctx); }
                catch (Exception err)
                {
                    try
                    {
                        var body = Encoding.UTF8.GetBytes(err.ToString());
                        ctx.Response.StatusCode = 500;
                        ctx.Response.ContentLength64 = body.Length;
                        ctx.Response.OutputStream.Write(body);
                        ctx.Response.Close();
                    }
                    catch { /* The client sees a closed connection. */ }
                }
            });
        }
    }

    // The stub's handlers, keyed by "METHOD /path" ("* /path" for any method). A table lookup picks the
    // handler, so no handler is guarded by comparing the request's path or method string (CodeQL
    // cs/user-controlled-bypass).
    Dictionary<string, Action<HttpListenerContext, string>>? routes;

    Dictionary<string, Action<HttpListenerContext, string>> Routes() => routes ??= new()
    {
        ["* /.well-known/openid-configuration"] = Discovery,
        ["* /jwks"] = Jwks,
        ["* /userinfo"] = UserInfo,
        ["POST /par"] = Par,
        ["* /authorize"] = Authorize,
        ["POST /token"] = Token,
    };

    void Handle(HttpListenerContext exchange)
    {
        using var reader = new StreamReader(exchange.Request.InputStream, exchange.Request.ContentEncoding);
        var text = reader.ReadToEnd();
        var path = exchange.Request.Url!.AbsolutePath;
        var table = Routes();
        var handler = table.GetValueOrDefault(exchange.Request.HttpMethod + " " + path) ?? table.GetValueOrDefault("* " + path) ?? NotFound;
        handler(exchange, text);
    }

    void NotFound(HttpListenerContext exchange, string text)
    {
        Json(exchange, 404, new Dictionary<string, object?> { ["error"] = "not_found" });
    }

    void Discovery(HttpListenerContext exchange, string text)
    {
        Json(exchange, 200, Metadata());
    }

    void Jwks(HttpListenerContext exchange, string text)
    {
        Json(exchange, 200, new Dictionary<string, object?> { ["keys"] = new List<object?> { ProviderJwk } });
    }

    void UserInfo(HttpListenerContext exchange, string text)
    {
        var header = exchange.Request.Headers["Authorization"] ?? "";
        var token = header.StartsWith("Bearer ", StringComparison.Ordinal) ? header[7..].Trim() : "";
        State.Access.TryGetValue(token, out var claims);
        Json(exchange, claims == null ? 401 : 200, claims ?? new Dictionary<string, object?> { ["error"] = "invalid_token" });
    }

    void Par(HttpListenerContext exchange, string text)
    {
        if (!Authorized(exchange, text)) { Json(exchange, 401, new Dictionary<string, object?> { ["error"] = "invalid_client" }); return; }
        var requestUri = "urn:par:" + Guid.NewGuid().ToString("N");
        State.Pushed[requestUri] = Form(text);
        Json(exchange, 201, new Dictionary<string, object?> { ["request_uri"] = requestUri, ["expires_in"] = 60 });
    }

    void Authorize(HttpListenerContext exchange, string text)
    {
        var query = Form(exchange.Request.Url!.Query.TrimStart('?'));
        var stored = query.GetValueOrDefault("request_uri");
        var parameters = stored == null ? query : State.Pushed.GetValueOrDefault(stored);
        if (parameters == null) { Json(exchange, 400, new Dictionary<string, object?> { ["error"] = "invalid_request" }); return; }
        var redirect = parameters.GetValueOrDefault("redirect_uri") ?? "";
        var state = parameters.GetValueOrDefault("state") ?? "";
        var challenge = parameters.GetValueOrDefault("code_challenge") ?? "";
        if (parameters.GetValueOrDefault("code_challenge_method") != "S256" || challenge.Length == 0)
        {
            Json(exchange, 400, new Dictionary<string, object?> { ["error"] = "invalid_request" });
            return;
        }
        var row = new Dictionary<string, string>
        {
            ["sub"] = "user-1", ["email"] = "user-1@example.com", ["sid"] = "sid-1",
            ["nonce"] = parameters.GetValueOrDefault("nonce") ?? "", ["redirect"] = redirect, ["challenge"] = challenge,
        };
        var code = Guid.NewGuid().ToString("N");
        State.Codes[code] = row;
        var back = new Uri(redirect);
        var location = back.GetComponents(UriComponents.SchemeAndServer, UriFormat.SafeUnescaped)
            + (string.IsNullOrEmpty(back.AbsolutePath) ? "/" : back.AbsolutePath)
            + "?code=" + Uri.EscapeDataString(code) + "&state=" + Uri.EscapeDataString(state) + "&iss=" + Uri.EscapeDataString(State.Url);
        exchange.Response.StatusCode = 302;
        exchange.Response.Headers["Location"] = location;
        exchange.Response.ContentLength64 = 0;
        exchange.Response.Close();
    }

    void Token(HttpListenerContext exchange, string text)
    {
        if (!Authorized(exchange, text))
        {
            Json(exchange, 401, new Dictionary<string, object?> { ["error"] = "invalid_client", ["error_description"] = "client authentication failed" });
            return;
        }
        var parameters = Form(text);
        var grant = parameters.GetValueOrDefault("grant_type") ?? "";
        if (grant == "client_credentials")
        {
            Json(exchange, 200, new Dictionary<string, object?> { ["access_token"] = "cc-token", ["token_type"] = "Bearer", ["expires_in"] = 120, ["scope"] = parameters.GetValueOrDefault("scope") ?? "" });
            return;
        }
        if (grant == "refresh_token")
        {
            if (!State.Refresh.TryGetValue(parameters.GetValueOrDefault("refresh_token") ?? "", out var row))
            {
                Json(exchange, 400, new Dictionary<string, object?> { ["error"] = "invalid_grant" });
                return;
            }
            var minted = TokenFor(row!);
            var claims = new Dictionary<string, object?>(State.Access[(string)minted["access_token"]!]);
            claims.Remove("nonce");
            minted["id_token"] = IdTokenOf(claims, false);
            Json(exchange, 200, minted);
            return;
        }
        var code = parameters.GetValueOrDefault("code") ?? "";
        if (!State.Codes.TryGetValue(code, out var saved) || saved["redirect"] != parameters.GetValueOrDefault("redirect_uri"))
        {
            Json(exchange, 400, new Dictionary<string, object?> { ["error"] = "invalid_grant" });
            return;
        }
        var verifier = parameters.GetValueOrDefault("code_verifier") ?? "";
        var got = Codec.B64UrlEncode(SHA256.HashData(Encoding.UTF8.GetBytes(verifier)));
        if (got != saved["challenge"])
        {
            Json(exchange, 400, new Dictionary<string, object?> { ["error"] = "invalid_grant", ["error_description"] = "pkce" });
            return;
        }
        State.Codes.Remove(code);
        Json(exchange, 200, TokenFor(saved));
    }

    Dictionary<string, object?> Metadata()
    {
        var doc = new Dictionary<string, object?>
        {
            ["issuer"] = State.Url,
            ["authorization_endpoint"] = State.Url + "/authorize",
            ["token_endpoint"] = State.Url + "/token",
            ["jwks_uri"] = State.Url + "/jwks",
            ["userinfo_endpoint"] = State.Url + "/userinfo",
            ["end_session_endpoint"] = State.Url + "/end-session",
            ["response_types_supported"] = new List<object?> { "code" },
            ["subject_types_supported"] = new List<object?> { "public" },
            ["id_token_signing_alg_values_supported"] = new List<object?> { "RS256" },
            ["token_endpoint_auth_methods_supported"] = new List<object?> { "client_secret_basic", "client_secret_post", "private_key_jwt" },
            ["code_challenge_methods_supported"] = new List<object?> { "S256" },
            ["authorization_response_iss_parameter_supported"] = true,
            ["scopes_supported"] = Scopes.Split(' ').Cast<object?>().ToList(),
        };
        if (State.Par) doc["pushed_authorization_request_endpoint"] = State.Url + "/par";
        return doc;
    }

    Dictionary<string, object?> TokenFor(Dictionary<string, string> row)
    {
        var access = Guid.NewGuid().ToString("N");
        var refresh = Guid.NewGuid().ToString("N");
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var payload = new Dictionary<string, object?>
        {
            ["iss"] = State.Url, ["sub"] = row["sub"], ["aud"] = State.Aud,
            ["exp"] = State.Exp ?? now + 300, ["iat"] = State.Exp ?? now, ["nonce"] = row["nonce"],
            ["email"] = row["email"], ["name"] = "Demo User", ["preferred_username"] = row["sub"], ["sid"] = row["sid"],
            ["at_hash"] = State.BadAtHash ? "aaaa" : IdToken.HashClaim(access, "RS256"),
        };
        var token = IdTokenOf(payload, State.Corrupt);
        State.Refresh[refresh] = row;
        State.Access[access] = payload;
        State.Aud = Client;
        State.Corrupt = false;
        State.BadAtHash = false;
        State.Exp = null;
        return new Dictionary<string, object?>
        {
            ["access_token"] = access, ["token_type"] = "Bearer", ["expires_in"] = 300,
            ["refresh_token"] = refresh, ["id_token"] = token, ["scope"] = Scopes,
        };
    }

    string IdTokenOf(Dictionary<string, object?> payload, bool corrupt)
    {
        var header = Codec.B64UrlEncode(Encoding.UTF8.GetBytes("{\"alg\":\"RS256\",\"kid\":\"op\",\"typ\":\"JWT\"}"));
        var body = Codec.B64UrlEncode(Encoding.UTF8.GetBytes(Jsons.Write(payload)));
        var signature = ProviderKeys.SignData(Encoding.ASCII.GetBytes(header + "." + body), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var sig = Codec.B64UrlEncode(signature);
        if (corrupt) sig = (sig.StartsWith('A') ? "B" : "A") + sig[1..];
        return header + "." + body + "." + sig;
    }

    bool Authorized(HttpListenerContext exchange, string body)
    {
        var header = exchange.Request.Headers["Authorization"] ?? "";
        if (header.StartsWith("Basic ", StringComparison.Ordinal))
        {
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(header[6..]));
            return decoded == Client + ":" + Secret;
        }
        var parameters = Form(body);
        if (parameters.ContainsKey("client_secret")) return Client == parameters.GetValueOrDefault("client_id") && Secret == parameters.GetValueOrDefault("client_secret");
        var assertion = parameters.GetValueOrDefault("client_assertion");
        return !string.IsNullOrEmpty(assertion) && ClientOk(assertion);
    }

    bool ClientOk(string assertion)
    {
        var parts = assertion.Split('.');
        if (parts.Length != 3) return false;
        var header = Jsons.Map(Jsons.Read(Encoding.UTF8.GetString(Codec.B64UrlDecode(parts[0], "header"))));
        var payload = Jsons.Map(Jsons.Read(Encoding.UTF8.GetString(Codec.B64UrlDecode(parts[1], "payload"))));
        if (header == null || payload == null || !Equals(header.GetValueOrDefault("alg"), "RS256")) return false;
        var signature = Codec.B64UrlDecode(parts[2], "signature");
        if (!ClientKeys.VerifyData(Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)) return false;
        var audiences = Jsons.List(payload.GetValueOrDefault("aud"))?.Select(item => Convert.ToString(item)).ToList()
            ?? new List<string?> { Convert.ToString(payload.GetValueOrDefault("aud")) };
        return Equals(payload.GetValueOrDefault("iss"), Client) && Equals(payload.GetValueOrDefault("sub"), Client) && audiences.Contains(State.Url);
    }

    public static void Json(HttpListenerContext exchange, int status, object body)
    {
        var raw = Encoding.UTF8.GetBytes(Jsons.Write(body));
        exchange.Response.StatusCode = status;
        exchange.Response.ContentType = "application/json";
        exchange.Response.ContentLength64 = raw.Length;
        exchange.Response.OutputStream.Write(raw);
        exchange.Response.Close();
    }

    public static Dictionary<string, string> Form(string? text)
    {
        var output = new Dictionary<string, string>();
        if (string.IsNullOrEmpty(text)) return output;
        foreach (var part in text.Split('&'))
        {
            var at = part.IndexOf('=');
            var key = Uri.UnescapeDataString((at < 0 ? part : part[..at]).Replace("+", " "));
            var value = Uri.UnescapeDataString((at < 0 ? "" : part[(at + 1)..]).Replace("+", " "));
            output[key] = value;
        }
        return output;
    }

    public static Dictionary<string, object?> Jwk(RSA key, string kid)
    {
        var parameters = key.ExportParameters(false);
        return new Dictionary<string, object?>
        {
            ["kty"] = "RSA", ["n"] = Codec.B64UrlEncode(parameters.Modulus!), ["e"] = Codec.B64UrlEncode(parameters.Exponent!),
            ["kid"] = kid, ["alg"] = "RS256", ["use"] = "sig",
        };
    }

    static string ProviderKeysExport(RSA key) => key.ExportPkcs8PrivateKeyPem();

    public static int FreePort()
    {
        var tcp = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        tcp.Start();
        var port = ((IPEndPoint)tcp.LocalEndpoint).Port;
        tcp.Stop();
        return port;
    }

    public sealed class Stub
    {
        public string Url = "";
        public bool Par;
        public bool Corrupt;
        public string Aud = Client;
        public long? Exp;
        public bool BadAtHash;
        public readonly Dictionary<string, Dictionary<string, string>> Codes = new();
        public readonly Dictionary<string, Dictionary<string, string>> Refresh = new();
        public readonly Dictionary<string, Dictionary<string, object?>> Access = new();
        public readonly Dictionary<string, Dictionary<string, string>> Pushed = new();
    }
}

public class RelyingPartyTests : IClassFixture<ProviderFixture>
{
    readonly ProviderFixture fx;
    public RelyingPartyTests(ProviderFixture fixture) => fx = fixture;

    [Fact]
    public void DefaultScopesAndAtHash()
    {
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes("abc"));
        Assert.Equal(ProviderFixture.Scopes, Discovery.DefaultScopes);
        Assert.Equal(Codec.B64UrlEncode(digest[..(digest.Length / 2)]), IdToken.HashClaim("abc", "RS256"));
    }

    [Fact]
    public void SignsInWithPkce()
    {
        var rp = RelyingParty.Create(ConfigMap());
        var signed = SignIn(rp);
        Assert.Equal("user-1", signed.Login.Subject);
        Assert.Equal("user-1@example.com", signed.Login.Email);
        Assert.Equal("sid-1", signed.Login.Sid);
        Assert.Equal(fx.State.Url, signed.Login.Issuer);
        Assert.Equal("user-1", signed.Login.PreferredUsername);
        Assert.NotNull(signed.Login.RefreshToken);
        Assert.Contains("code_challenge=", signed.Request.Url);
        Assert.Contains("code_challenge_method=S256", signed.Request.Url);
        Assert.DoesNotContain("client_secret", signed.Request.Url);
        Assert.Equal("user-1", rp.UserInfo(signed.Login.AccessToken, signed.Login.Subject)["sub"]);
        var end = rp.EndSessionUrl(signed.Login.IdToken, "bye");
        Assert.Contains("/end-session", end);
        Assert.Contains("id_token_hint=", end);
        Assert.Contains("client_id=", end);
    }

    [Fact]
    public void RefusesACallbackThatIsNotThisSignIn()
    {
        var rp = RelyingParty.Create(ConfigMap());
        var request = rp.Authorize();
        var query = Query(Manual(request.Url!).Location!);
        var wrongState = Copy(request);
        wrongState.State = "nope";
        AssertMessage("state", () => rp.Complete(query, wrongState));
        var wrongNonce = Copy(request);
        wrongNonce.Nonce = "nope";
        AssertMessage("nonce", () => rp.Complete(query, wrongNonce));
        query["iss"] = "https://elsewhere.example";
        AssertMessage("iss mismatch", () => rp.Complete(query, request));
        query["iss"] = fx.State.Url;
        query["access_token"] = "should-not-be-here";
        AssertMessage("access_token", () => rp.Complete(query, request));
    }

    [Fact]
    public void AcceptsACodeOnce()
    {
        var rp = RelyingParty.Create(ConfigMap());
        var signed = SignIn(rp);
        Assert.Equal("user-1", signed.Login.Subject);
        AssertMessage("already used", () => rp.Complete(signed.Query, signed.Request));
    }

    [Fact]
    public void RefusesBadTokens()
    {
        var rp = RelyingParty.Create(ConfigMap());
        var wrongConfig = ConfigMap();
        wrongConfig["clientSecret"] = "nope";
        var wrong = RelyingParty.Create(wrongConfig);
        var request = wrong.Authorize();
        var query = Query(Manual(request.Url!).Location!);
        var invalid = Assert.Throws<OidcError>(() => wrong.Complete(query, request));
        Assert.Equal("invalid_client", invalid.OauthError);
        fx.State.Corrupt = true;
        AssertMessage("signature", () => SignIn(rp));
        fx.State.Aud = "other-client";
        AssertMessage("audience|aud", () => SignIn(rp));
        fx.State.Exp = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 3600;
        AssertMessage("exp|timestamp|old|iat", () => SignIn(rp));
        fx.State.BadAtHash = true;
        AssertMessage("at_hash", () => SignIn(rp));
    }

    [Fact]
    public void RefreshAndClientCredentials()
    {
        var rp = RelyingParty.Create(ConfigMap());
        var login = SignIn(rp).Login;
        var refreshed = rp.Refresh(login.RefreshToken, login);
        Assert.Equal(login.Subject, refreshed.Subject);
        Assert.NotEqual(login.AccessToken, refreshed.AccessToken);
        Assert.Equal("cc-token", rp.ClientCredentials("ssf.manage").AccessToken);
        Assert.Equal("cc-token", rp.ClientCredentials("ssf.manage").AccessToken);
    }

    [Fact]
    public void ParPushesTheRequest()
    {
        fx.State.Par = true;
        try
        {
            var rp = RelyingParty.Create(ConfigMap());
            var signed = SignIn(rp);
            Assert.Contains("request_uri=", signed.Request.Url);
            Assert.DoesNotContain("code_challenge=", signed.Request.Url);
            Assert.Equal("user-1", signed.Login.Subject);
        }
        finally { fx.State.Par = false; }
    }

    [Fact]
    public void PostAndPrivateKeyJwt()
    {
        var posted = ConfigMap();
        posted["tokenEndpointAuthMethod"] = "client_secret_post";
        Assert.Equal("user-1", SignIn(RelyingParty.Create(posted)).Login.Subject);
        var jwt = ConfigMap();
        jwt["tokenEndpointAuthMethod"] = "private_key_jwt";
        jwt.Remove("clientSecret");
        jwt["privateKeyPem"] = fx.ClientPem;
        Assert.Equal("user-1", SignIn(RelyingParty.Create(jwt)).Login.Subject);
    }

    [Fact]
    public void ReadsConfigurationFileNames()
    {
        var directory = Directory.CreateTempSubdirectory("oidc-config-");
        File.WriteAllText(Path.Combine(directory.FullName, "secret"), "from-file\n");
        Config.Environment = name => name == "OIDC_TEST_SECRET" ? "from-env" : System.Environment.GetEnvironmentVariable(name);
        try
        {
            var file = BaseFile();
            file["clientSecret"] = "env:OIDC_TEST_SECRET";
            file["scopes"] = ProviderFixture.Scopes.Split(' ').Cast<object?>().ToList();
            var env = Config.ResolveConfig(file, directory.FullName);
            Assert.Equal(ProviderFixture.Client, env["clientId"]);
            Assert.Equal("from-env", env["clientSecret"]);
            Assert.Equal("https://localhost:8081", env["issuer"]);
            Assert.Equal(ProviderFixture.Scopes, env["scopes"]);
            Assert.Equal("client_secret_basic", env["tokenEndpointAuthMethod"]);
            var fromFile = new Dictionary<string, object?>(file) { ["clientSecret"] = "file:secret" };
            Assert.Equal("from-file", Config.ResolveConfig(fromFile, directory.FullName)["clientSecret"]);
            var chain = "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n";
            File.WriteAllText(Path.Combine(directory.FullName, "ca.pem"), chain);
            Assert.Equal(chain, Config.ResolveConfig(With(file, "tlsCa", "ca.pem"), directory.FullName)["tlsCa"]);
            Assert.Equal(chain, Config.ResolveConfig(With(file, "tlsCa", "file:ca.pem"), directory.FullName)["tlsCa"]);
            Assert.Equal(chain.Trim(), Config.ResolveConfig(With(file, "tlsCa", chain), directory.FullName)["tlsCa"]);
            Config.Environment = name => name == "OIDC_TEST_CA" ? chain : name == "OIDC_TEST_SECRET" ? "from-env" : System.Environment.GetEnvironmentVariable(name);
            Assert.Equal(chain, Config.ResolveConfig(With(file, "tlsCa", "env:OIDC_TEST_CA"), directory.FullName)["tlsCa"]);
            Config.Environment = name => name == "OIDC_TEST_SECRET" ? "from-env" : System.Environment.GetEnvironmentVariable(name);
            Assert.Null(Config.ResolveConfig(With(file, "tlsCa", "env:OIDC_TEST_CA"), directory.FullName).GetValueOrDefault("tlsCa"));
            Assert.Null(Config.ResolveConfig(With(file, "tlsCa", "missing.pem"), directory.FullName).GetValueOrDefault("tlsCa"));
            AssertMessage("public client", () => Config.ResolveConfig(With(file, "tokenEndpointAuthMethod", "none"), directory.FullName));
            AssertMessage("openid", () => Config.ResolveConfig(With(file, "scopes", "profile email"), directory.FullName));
        }
        finally { Config.Environment = static name => System.Environment.GetEnvironmentVariable(name); }
    }

    [Fact]
    public void SignalsFlag()
    {
        var file = BaseFile();
        file["clientSecret"] = "secret";
        file["ssf"] = new Dictionary<string, object?> { ["transmitter"] = "https://localhost:8081/", ["pollIntervalMs"] = 3000 };
        var omitted = Config.ResolveConfig(file, ".");
        Assert.Equal(ProviderFixture.Scopes, omitted["scopes"]);
        Assert.False(omitted.ContainsKey("signals"));
        var ssf = (Dictionary<string, object?>)omitted["ssf"]!;
        Assert.Equal("https://localhost:8081", ssf["transmitter"]);
        Assert.Equal(3000, Convert.ToInt32(ssf["pollIntervalMs"]));
        var explicitOn = new Dictionary<string, object?>(file) { ["signals"] = true, ["scopes"] = ProviderFixture.Scopes };
        var on = Config.ResolveConfig(explicitOn, ".");
        Assert.Equal(ProviderFixture.Scopes, on["scopes"]);
        Assert.False(on.ContainsKey("signals"));
        Assert.Equal("https://localhost:8081", ((Dictionary<string, object?>)on["ssf"]!)["transmitter"]);
        var listedDoc = new Dictionary<string, object?>(file)
        {
            ["signals"] = false,
            ["scopes"] = ProviderFixture.Scopes,
            ["ssf"] = new Dictionary<string, object?> { ["transmitter"] = "not-a-url" },
        };
        var listed = Config.ResolveConfig(listedDoc, ".");
        Assert.Equal(false, listed["signals"]);
        Assert.False(listed.ContainsKey("ssf"));
        Assert.Equal("openid profile email offline_access", listed["scopes"]);
        Assert.DoesNotContain("ssf.read", Convert.ToString(listed["scopes"])!.Split(' '));
        Assert.DoesNotContain("ssf.manage", Convert.ToString(listed["scopes"])!.Split(' '));
        var defaults = Config.ResolveConfig(new Dictionary<string, object?>(file) { ["signals"] = false }, ".");
        Assert.Equal(false, defaults["signals"]);
        Assert.False(defaults.ContainsKey("ssf"));
        Assert.Equal("openid profile email offline_access", defaults["scopes"]);
        Assert.Contains("openid", Convert.ToString(defaults["scopes"])!.Split(' '));
        AssertMessage("openid", () => Config.ResolveConfig(With(With(file, "signals", false), "scopes", "ssf.read ssf.manage"), "."));
        var bad = Assert.Throws<OidcError>(() => Config.ResolveConfig(With(file, "signals", "no"), "."));
        Assert.Equal("config", bad.Code);
        Assert.Equal("signals must be true or false", bad.Message);
    }

    Dictionary<string, object?> ConfigMap() => new()
    {
        ["metadataUrl"] = fx.State.Url + "/.well-known/openid-configuration",
        ["clientId"] = ProviderFixture.Client,
        ["clientSecret"] = ProviderFixture.Secret,
        ["tokenEndpointAuthMethod"] = "client_secret_basic",
        ["redirectUri"] = "http://127.0.0.1/callback",
        ["postLogoutRedirectUri"] = "http://127.0.0.1/",
        ["scopes"] = ProviderFixture.Scopes,
        ["privateKeyAlg"] = "RS256",
        ["par"] = "auto",
        ["clockToleranceSec"] = 30,
        ["maxIdTokenAgeSec"] = 600,
        ["allowInsecure"] = true,
    };

    static Dictionary<string, object?> BaseFile() => new()
    {
        ["metadataUrl"] = "https://localhost:8081/.well-known/openid-configuration",
        ["client_id"] = ProviderFixture.Client,
        ["clientSecret"] = "env:OIDC_TEST_SECRET",
        ["redirectUri"] = "http://localhost:3000/callback",
    };

    static Dictionary<string, object?> With(Dictionary<string, object?> file, string key, object? value)
    {
        var copy = new Dictionary<string, object?>(file);
        copy[key] = value;
        return copy;
    }

    Signed SignIn(RelyingParty rp)
    {
        var request = rp.Authorize();
        var manual = Manual(request.Url!);
        Assert.NotNull(manual.Location);
        var query = Query(manual.Location!);
        return new Signed(request, query, rp.Complete(query, request));
    }

    static RedirectResult Manual(string url)
    {
        using var client = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false, UseProxy = false });
        using var response = client.GetAsync(url).GetAwaiter().GetResult();
        response.Headers.TryGetValues("Location", out var locations);
        return new RedirectResult((int)response.StatusCode, locations?.FirstOrDefault());
    }

    static Dictionary<string, string> Query(string location)
    {
        var uri = new Uri(location);
        return ProviderFixture.Form(uri.Query.TrimStart('?'));
    }

    static RelyingParty.Transaction Copy(RelyingParty.Transaction request) => new()
    {
        Url = request.Url, State = request.State, Nonce = request.Nonce, CodeVerifier = request.CodeVerifier,
        RedirectUri = request.RedirectUri, MaxAge = request.MaxAge, ExpectedSub = request.ExpectedSub,
    };

    static void AssertMessage(string pattern, Action call)
    {
        var err = Assert.Throws<OidcError>(call);
        Assert.True(Regex.IsMatch(err.Message, pattern), err.Message);
    }

    readonly record struct RedirectResult(int Status, string? Location);
    readonly record struct Signed(RelyingParty.Transaction Request, Dictionary<string, string> Query, RelyingParty.Login Login);
}
