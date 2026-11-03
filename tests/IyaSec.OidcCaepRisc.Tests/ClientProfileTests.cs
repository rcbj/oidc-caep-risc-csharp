// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using System.Text.RegularExpressions;
using IyaSec.Oidc;
using Xunit;

namespace IyaSec.OidcCaepRisc.Tests;

// Issue #30: DPoP, acr enforced, PAR required by the provider, RS256 by default, typ and at_hash
// required, the same checks on every way of creating a client, and the session token cache.
public class ClientProfileTests : IClassFixture<ProviderFixture>
{
    static readonly List<object?> Es256 = new() { "ES256" };
    readonly ProviderFixture fx;

    public ClientProfileTests(ProviderFixture fixture)
    {
        fx = fixture;
        fx.State.Reset();
    }

    // 1. DPoP

    [Fact]
    public void DpopAutoProvesEveryRequestAndBindsEveryToken()
    {
        fx.State.DpopAlgs = new List<object?> { "RS256", "ES256" };
        fx.State.Par = true;
        var rp = RelyingParty.Create(ConfigMap());
        Assert.True(rp.UsesDpop);
        var signed = SignIn(rp, null, "dpop-1");
        Assert.Equal(1, fx.State.ParProofs);
        Assert.Equal(rp.DpopSigner!.Thumbprint, fx.State.LastParameters!["dpop_jkt"]);
        Assert.Equal("DPoP", signed.Login.TokenType);
        Assert.Equal("user-1", rp.UserInfo(signed.Login.AccessToken, "user-1")["sub"]);
        Assert.Equal(1, fx.State.UserInfoProofs);
        var refreshed = rp.Refresh(signed.Login.RefreshToken, signed.Login);
        Assert.Equal("DPoP", refreshed.TokenType);
        var minted = rp.ClientCredentials("ssf.manage");
        Assert.Equal("DPoP", minted.TokenType);
        Assert.Equal(new[] { "authorization_code", "refresh_token", "client_credentials" }, fx.State.TokenProofs);
        Assert.Empty(fx.State.ProofErrors);
    }

    [Fact]
    public void DpopJktIsOnTheAuthorizationRequestWithoutPar()
    {
        fx.State.DpopAlgs = Es256;
        var rp = RelyingParty.Create(ConfigMap());
        var request = rp.Authorize();
        Assert.Contains("dpop_jkt=" + rp.DpopSigner!.Thumbprint, request.Url);
        Complete(rp, request, null);
        Assert.Equal(new[] { "authorization_code" }, fx.State.TokenProofs);
    }

    [Fact]
    public void DpopModes()
    {
        var always = With(ConfigMap(), "dpop", "always");
        AssertMessage("dpop_signing_alg_values_supported", () => RelyingParty.Create(always));
        fx.State.DpopAlgs = new List<object?> { "PS256" };
        AssertMessage("ES256", () => RelyingParty.Create(always));
        Assert.False(RelyingParty.Create(ConfigMap()).UsesDpop);
        fx.State.DpopAlgs = Es256;
        Assert.True(RelyingParty.Create(always).UsesDpop);
        var never = RelyingParty.Create(With(ConfigMap(), "dpop", "never"));
        Assert.False(never.UsesDpop);
        Assert.Equal("Bearer", SignIn(never, null, null).Login.TokenType);
        Assert.DoesNotContain("dpop_jkt", never.Authorize().Url);
        Assert.Empty(fx.State.TokenProofs);
        AssertMessage("dpop must be", () => RelyingParty.Create(With(ConfigMap(), "dpop", "sometimes")));
    }

    [Fact]
    public void DpopNonceIsRetriedOnceAndRemembered()
    {
        fx.State.DpopAlgs = Es256;
        fx.State.TokenNonce = "as-nonce-1";
        fx.State.ResourceNonce = "rs-nonce-1";
        var rp = RelyingParty.Create(ConfigMap());
        var login = SignIn(rp, null, null).Login;
        Assert.Equal(1, fx.State.TokenChallenges);
        Assert.Equal("as-nonce-1", rp.DpopSigner!.NonceFor(fx.State.Url + "/token"));
        rp.Refresh(login.RefreshToken, login);
        Assert.Equal(1, fx.State.TokenChallenges);
        Assert.Equal("user-1", rp.UserInfo(login.AccessToken, "user-1")["sub"]);
        Assert.Equal(1, fx.State.ResourceChallenges);
        fx.State.TokenNonce = "as-nonce-2";
        rp.ClientCredentials("ssf.read");
        Assert.Equal(2, fx.State.TokenChallenges);
        Assert.Equal("as-nonce-2", rp.DpopSigner.NonceFor(fx.State.Url + "/token"));
        Assert.Empty(fx.State.ProofErrors);
    }

    [Fact]
    public void TokenTypeMustMatchWhetherAProofWasSent()
    {
        fx.State.DpopAlgs = Es256;
        fx.State.ForceTokenType = "Bearer";
        AssertMessage("token_type is Bearer.*must be DPoP", () => SignIn(RelyingParty.Create(ConfigMap()), null, null));
        fx.State.ForceTokenType = "dpop";
        Assert.Equal("dpop", SignIn(RelyingParty.Create(ConfigMap()), null, null).Login.TokenType);
        fx.State.DpopAlgs = null;
        fx.State.ForceTokenType = "DPoP";
        AssertMessage("token_type is DPoP.*must be Bearer", () => SignIn(RelyingParty.Create(ConfigMap()), null, null));
    }

    [Fact]
    public void DpopKeyNamesAPemKey()
    {
        fx.State.DpopAlgs = Es256;
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pem = key.ExportPkcs8PrivateKeyPem();
        var point = key.ExportParameters(false).Q;
        var expected = DpopProof.Thumbprint(Codec.B64UrlEncode(point.X!), Codec.B64UrlEncode(point.Y!));
        var first = RelyingParty.Create(With(ConfigMap(), "dpopKey", pem));
        var second = RelyingParty.Create(With(ConfigMap(), "dpopKey", pem));
        Assert.Equal(expected, first.DpopSigner!.Thumbprint);
        Assert.Equal(expected, second.DpopSigner!.Thumbprint);
        Assert.NotEqual(expected, RelyingParty.Create(ConfigMap()).DpopSigner!.Thumbprint);
        Assert.Equal("user-1", SignIn(first, null, null).Login.Subject);
        var directory = Directory.CreateTempSubdirectory("oidc-dpop-");
        File.WriteAllText(Path.Combine(directory.FullName, "dpop.pem"), pem);
        var file = new Dictionary<string, object?>(ConfigMap()) { ["dpopKey"] = "dpop.pem" };
        file.Remove("clientSecret");
        file["clientSecret"] = ProviderFixture.Secret;
        Assert.Equal(pem.Trim(), Config.ResolveConfig(FileOf(file), directory.FullName)["dpopKey"]);
        using var big = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        AssertMessage("P-256", () => RelyingParty.Create(With(ConfigMap(), "dpopKey", big.ExportPkcs8PrivateKeyPem())));
    }

    [Fact]
    public void ProofCarriesTheRequiredClaims()
    {
        using var signer = new Dpop();
        var proof = signer.Proof("get", "https://rs.example/api/x?a=1#frag", "token-1");
        var check = DpopProof.Check(proof, "GET", "https://rs.example/api/x", "token-1");
        Assert.Null(check.Error);
        Assert.Equal(signer.Thumbprint, check.Jkt);
        Assert.False(check.Payload.ContainsKey("nonce"));
        var second = DpopProof.Check(signer.Proof("POST", "https://as.example/token"), "POST", "https://as.example/token", null);
        Assert.Null(second.Error);
        Assert.NotEqual(check.Payload["jti"], second.Payload["jti"]);
    }

    // 2. acr

    [Fact]
    public void AcrIsEnforced()
    {
        var rp = RelyingParty.Create(ConfigMap());
        var options = new RelyingParty.AuthorizeOptions { AcrValues = "urn:acr:a urn:acr:b" };
        fx.State.Acr = "urn:acr:b";
        var signed = SignIn(rp, options, null);
        Assert.Equal("urn:acr:a urn:acr:b", signed.Request.AcrValues);
        Assert.Equal("urn:acr:a urn:acr:b", fx.State.LastParameters!["acr_values"]);
        fx.State.Acr = "urn:acr:c";
        AssertMessage("acr urn:acr:c is not one of the requested", () => SignIn(rp, options, null));
        fx.State.Acr = null;
        AssertMessage("has no acr", () => SignIn(rp, options, null));
        fx.State.Acr = "urn:acr:other";
        Assert.Equal("user-1", SignIn(rp, null, null).Login.Subject);
        var configured = RelyingParty.Create(With(ConfigMap(), "acrValues", new List<object?> { "urn:acr:a" }));
        AssertMessage("acr urn:acr:other", () => SignIn(configured, null, null));
        fx.State.Acr = "urn:acr:a";
        var login = SignIn(configured, null, null).Login;
        // The refresh path does not re-check acr.
        fx.State.Acr = "urn:acr:changed";
        Assert.Equal("user-1", configured.Refresh(login.RefreshToken, login).Subject);
    }

    // 3. PAR required by the provider

    [Fact]
    public void ParRequiredByTheProvider()
    {
        fx.State.Par = true;
        fx.State.RequirePar = true;
        AssertMessage("requires pushed authorization", () => RelyingParty.Create(With(ConfigMap(), "par", "never")));
        var rp = RelyingParty.Create(ConfigMap());
        Assert.Equal(true, rp.Metadata["require_pushed_authorization_requests"]);
        var signed = SignIn(rp, null, null);
        Assert.Contains("request_uri=", signed.Request.Url);
        Assert.Equal("user-1", signed.Login.Subject);
        fx.State.Par = false;
        AssertMessage("pushed_authorization_request_endpoint", () => RelyingParty.Create(ConfigMap()));
        // par always against a provider with no PAR endpoint fails at creation, not at Authorize.
        fx.State.RequirePar = false;
        AssertMessage("par is always, and the provider has no pushed authorization endpoint", () => RelyingParty.Create(With(ConfigMap(), "par", "always")));
    }

    // 4. ID token signing algorithms

    [Fact]
    public void Rs256OnlyByDefault()
    {
        var advertised = new List<object?> { "ES256", "RS256", "HS256", "PS256" };
        Assert.Equal(new[] { "RS256" }, RelyingParty.Create(Inline(advertised, null)).IdTokenSigningAlgorithms);
        AssertMessage("advertises none of the accepted", () => RelyingParty.Create(Inline(new List<object?> { "ES256", "PS256" }, null)));
        var widened = Inline(new List<object?> { "RS256" }, null);
        widened["idTokenSigningAlgs"] = new List<object?> { "ES256", "RS256" };
        Assert.Equal(new[] { "RS256" }, RelyingParty.Create(widened).IdTokenSigningAlgorithms);
        widened["metadata"] = Metadata(advertised);
        Assert.Equal(new[] { "ES256", "RS256" }, RelyingParty.Create(widened).IdTokenSigningAlgorithms);
        AssertMessage("none", () => RelyingParty.Create(With(Inline(advertised, null), "idTokenSigningAlgs", new List<object?> { "RS256", "none" })));
        AssertMessage("none", () => RelyingParty.Create(With(Inline(new List<object?> { "none", "RS256" }, null), "idTokenSignedResponseAlg", "none")));
        Assert.Equal(new[] { "PS256" }, RelyingParty.Create(With(Inline(advertised, null), "idTokenSignedResponseAlg", "PS256")).IdTokenSigningAlgorithms);
        AssertMessage("does not advertise id_token alg ES384", () => RelyingParty.Create(With(Inline(advertised, null), "idTokenSignedResponseAlg", "ES384")));
    }

    [Fact]
    public void SymmetricOnlyWhenNamed()
    {
        fx.State.IdAlgs = new List<object?> { "RS256", "HS256" };
        fx.State.IdAlg = "HS256";
        AssertMessage("HS256, which this client does not accept", () => SignIn(RelyingParty.Create(ConfigMap()), null, null));
        var named = RelyingParty.Create(With(ConfigMap(), "idTokenSigningAlgs", new List<object?> { "HS256" }));
        Assert.Equal("user-1", SignIn(named, null, null).Login.Subject);
        fx.State.IdAlg = "RS256";
        AssertMessage("RS256, which this client does not accept", () => SignIn(named, null, null));
    }

    // 5. typ and at_hash

    [Fact]
    public void TypAndAtHashRequired()
    {
        var rp = RelyingParty.Create(ConfigMap());
        fx.State.Typ = null;
        AssertMessage("no typ", () => SignIn(rp, null, null));
        fx.State.Typ = "application/JWT";
        Assert.Equal("user-1", SignIn(rp, null, null).Login.Subject);
        fx.State.Typ = "JWT";
        fx.State.NoAtHash = true;
        AssertMessage("no at_hash", () => SignIn(rp, null, null));
        var relaxed = RelyingParty.Create(With(ConfigMap(), "requireIdTokenTypAndAtHash", false));
        Assert.Equal("user-1", SignIn(relaxed, null, null).Login.Subject);
        fx.State.Typ = null;
        Assert.Equal("user-1", SignIn(relaxed, null, null).Login.Subject);
        fx.State.Typ = "at+jwt";
        AssertMessage("typ is at\\+jwt", () => SignIn(relaxed, null, null));
        fx.State.Typ = "JWT";
        fx.State.NoAtHash = false;
        fx.State.BadAtHash = true;
        AssertMessage("at_hash does not match", () => SignIn(relaxed, null, null));
        AssertMessage("requireIdTokenTypAndAtHash", () => RelyingParty.Create(With(ConfigMap(), "requireIdTokenTypAndAtHash", "yes")));
    }

    // 6. The same checks on every way of creating a client

    [Fact]
    public void CreateAppliesTheDefaults()
    {
        var bare = ConfigMap();
        bare.Remove("par");
        bare.Remove("clockToleranceSec");
        bare.Remove("maxIdTokenAgeSec");
        bare.Remove("scopes");
        bare.Remove("privateKeyAlg");
        var made = RelyingParty.Create(bare).ConfigMap;
        Assert.Equal("auto", made["par"]);
        Assert.Equal("auto", made["dpop"]);
        Assert.Equal(30L, Convert.ToInt64(made["clockToleranceSec"]));
        Assert.Equal(600L, Convert.ToInt64(made["maxIdTokenAgeSec"]));
        Assert.Equal(new object?[] { "RS256" }, ((List<object?>)made["idTokenSigningAlgs"]!).ToArray());
        Assert.Equal(true, made["requireIdTokenTypAndAtHash"]);
        Assert.Equal(Discovery.DefaultScopes, made["scopes"]);
        var file = Config.ResolveConfig(new Dictionary<string, object?>
        {
            ["metadataUrl"] = "https://localhost:8081/.well-known/openid-configuration",
            ["client_id"] = ProviderFixture.Client,
            ["clientSecret"] = "secret",
            ["redirectUri"] = "http://localhost:3000/callback",
        }, ".");
        foreach (var name in new[] { "par", "dpop", "clockToleranceSec", "maxIdTokenAgeSec", "requireIdTokenTypAndAtHash" })
        {
            Assert.Equal(Convert.ToString(made[name]), Convert.ToString(file[name]));
        }
        // maxIdTokenAgeSec applies without being set.
        fx.State.Iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 1000;
        AssertMessage("iat is too old", () => SignIn(RelyingParty.Create(bare), null, null));
        // An iat more than the tolerance in the future is refused.
        fx.State.Iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 300;
        AssertMessage("iat is in the future", () => SignIn(RelyingParty.Create(bare), null, null));
        fx.State.Iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 10;
        Assert.Equal("user-1", SignIn(RelyingParty.Create(bare), null, null).Login.Subject);
    }

    [Fact]
    public void RedirectRuleOnCreateAndPerRequest()
    {
        var advertised = new List<object?> { "RS256" };
        foreach (var good in new[] { "https://app.example/cb", "http://localhost:3000/cb", "http://127.0.0.1/cb", "http://[::1]:8080/cb" })
        {
            Assert.Equal(good, RelyingParty.Create(Inline(advertised, good)).ConfigMap["redirectUri"]);
        }
        AssertMessage("redirectUri must use https", () => RelyingParty.Create(Inline(advertised, "http://app.example/cb")));
        AssertMessage("redirectUri is not a URL", () => RelyingParty.Create(Inline(advertised, "app.example/cb")));
        // allowInsecure lets the provider's endpoints use http; it does not relax the redirect rule.
        AssertMessage("redirectUri must use https", () => RelyingParty.Create(With(Inline(advertised, "http://app.example/cb"), "allowInsecure", true)));
        AssertMessage("redirectUri must use https", () => RelyingParty.Create(With(ConfigMap(), "redirectUri", "http://app.example/cb")));
        AssertMessage("redirectUri is required", () => RelyingParty.Create(Inline(advertised, "")));
        AssertMessage("postLogoutRedirectUri must use https", () => RelyingParty.Create(With(Inline(advertised, null), "postLogoutRedirectUri", "http://app.example/")));
        var rp = RelyingParty.Create(Inline(advertised, null));
        AssertMessage("redirectUri must use https", () => rp.Authorize(new RelyingParty.AuthorizeOptions { RedirectUri = "http://evil.example/cb" }));
        AssertMessage("redirectUri is not a URL", () => rp.Authorize(new RelyingParty.AuthorizeOptions { RedirectUri = "javascript:alert(1)" }));
        var other = rp.Authorize(new RelyingParty.AuthorizeOptions { RedirectUri = "http://localhost:4000/other" });
        Assert.Equal("http://localhost:4000/other", other.RedirectUri);
    }

    // 7. The session token cache

    [Fact]
    public void SessionCacheReturnsAndRefreshesTokens()
    {
        fx.State.DpopAlgs = Es256;
        var rp = RelyingParty.Create(ConfigMap());
        var fresh = SignIn(rp, null, "s-1").Login;
        Assert.Equal("s-1", fresh.SessionId);
        Assert.Equal(fresh.AccessToken, rp.SessionAccessToken("s-1"));
        Assert.Single(fx.State.TokenProofs);
        fx.State.ExpiresIn = 20;
        var soon = SignIn(rp, null, "s-2").Login;
        var renewed = rp.SessionAccessToken("s-2");
        Assert.NotEqual(soon.AccessToken, renewed);
        Assert.Equal(renewed, rp.SessionStore.Get("s-2")!.AccessToken);
        Assert.Equal("DPoP", rp.SessionStore.Get("s-2")!.TokenType);
        Assert.Equal("user-1", rp.SessionStore.Get("s-2")!.Subject);
        Assert.Equal(new[] { "authorization_code", "authorization_code", "refresh_token" }, fx.State.TokenProofs);
        Assert.Equal("user-1", rp.UserInfo(renewed, "user-1")["sub"]);
        var handle = SignIn(rp, null, null).Login;
        Assert.False(string.IsNullOrEmpty(handle.SessionId));
        Assert.NotNull(rp.SessionStore.Get(handle.SessionId));
        rp.RemoveSession("s-1");
        Assert.Null(rp.SessionStore.Get("s-1"));
        var gone = Assert.Throws<OidcError>(() => rp.SessionAccessToken("s-1"));
        Assert.Equal("session", gone.Code);
        Assert.Empty(fx.State.ProofErrors);
    }

    [Fact]
    public void FailedRefreshRemovesTheSession()
    {
        var rp = RelyingParty.Create(ConfigMap());
        fx.State.ExpiresIn = 10;
        var login = SignIn(rp, null, "s-fail").Login;
        fx.State.Refresh.Remove(login.RefreshToken!);
        var refused = Assert.Throws<OidcError>(() => rp.SessionAccessToken("s-fail"));
        Assert.Equal("session", refused.Code);
        Assert.Equal("invalid_grant", refused.OauthError);
        Assert.Null(rp.SessionStore.Get("s-fail"));
        rp.SessionStore.Set("s-none", new SessionTokens { Subject = "user-1", AccessToken = "x", ExpiresAt = DateTime.UtcNow.AddSeconds(5) });
        Assert.Equal("session", Assert.Throws<OidcError>(() => rp.SessionAccessToken("s-none")).Code);
        Assert.Null(rp.SessionStore.Get("s-none"));
    }

    [Fact]
    public void SessionStoreIsReplaceable()
    {
        var store = new CountingStore();
        var rp = RelyingParty.Create(ConfigMap());
        rp.SessionStore = store;
        SignIn(rp, null, "s-shared");
        Assert.Equal(1, store.Sets);
        Assert.NotNull(rp.SessionAccessToken("s-shared"));
        rp.RemoveSession("s-shared");
        Assert.Equal(1, store.Removes);
        var bounded = new MemorySessionTokenStore(2);
        bounded.Set("a", new SessionTokens());
        bounded.Set("b", new SessionTokens());
        bounded.Set("c", new SessionTokens());
        Assert.Null(bounded.Get("a"));
        Assert.NotNull(bounded.Get("c"));
    }

    sealed class CountingStore : ISessionTokenStore
    {
        readonly Dictionary<string, SessionTokens> held = new();
        public int Sets;
        public int Removes;
        public SessionTokens? Get(string sessionId) => held.GetValueOrDefault(sessionId);
        public void Set(string sessionId, SessionTokens tokens) { Sets += 1; held[sessionId] = tokens; }
        public void Remove(string sessionId) { Removes += 1; held.Remove(sessionId); }
    }

    Dictionary<string, object?> ConfigMap() => new()
    {
        ["metadataUrl"] = fx.State.Url + "/.well-known/openid-configuration",
        ["clientId"] = ProviderFixture.Client,
        ["clientSecret"] = ProviderFixture.Secret,
        ["tokenEndpointAuthMethod"] = "client_secret_basic",
        ["redirectUri"] = "http://127.0.0.1/callback",
        ["scopes"] = ProviderFixture.Scopes,
        ["privateKeyAlg"] = "RS256",
        ["par"] = "auto",
        ["clockToleranceSec"] = 30,
        ["maxIdTokenAgeSec"] = 600,
        ["allowInsecure"] = true,
    };

    static Dictionary<string, object?> FileOf(Dictionary<string, object?> config)
    {
        var file = new Dictionary<string, object?>(config);
        file.Remove("allowInsecure");
        file["metadataUrl"] = "https://localhost:8081/.well-known/openid-configuration";
        return file;
    }

    static Dictionary<string, object?> Metadata(List<object?> idAlgs) => new()
    {
        ["issuer"] = "https://op.example",
        ["authorization_endpoint"] = "https://op.example/authorize",
        ["token_endpoint"] = "https://op.example/token",
        ["jwks_uri"] = "https://op.example/jwks",
        ["response_types_supported"] = new List<object?> { "code" },
        ["subject_types_supported"] = new List<object?> { "public" },
        ["id_token_signing_alg_values_supported"] = idAlgs,
    };

    static Dictionary<string, object?> Inline(List<object?> idAlgs, string? redirectUri) => new()
    {
        ["metadata"] = Metadata(idAlgs),
        ["clientId"] = ProviderFixture.Client,
        ["clientSecret"] = ProviderFixture.Secret,
        ["redirectUri"] = redirectUri ?? "https://app.example/callback",
    };

    static Dictionary<string, object?> With(Dictionary<string, object?> config, string key, object? value)
    {
        var copy = new Dictionary<string, object?>(config);
        copy[key] = value;
        return copy;
    }

    Signed SignIn(RelyingParty rp, RelyingParty.AuthorizeOptions? options, string? sessionId)
    {
        var request = rp.Authorize(options);
        return new Signed(request, Complete(rp, request, sessionId));
    }

    static RelyingParty.Login Complete(RelyingParty rp, RelyingParty.Transaction request, string? sessionId)
    {
        using var client = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false, UseProxy = false });
        using var response = client.GetAsync(request.Url).GetAwaiter().GetResult();
        response.Headers.TryGetValues("Location", out var locations);
        var location = locations?.FirstOrDefault();
        Assert.NotNull(location);
        var query = ProviderFixture.Form(new Uri(location!).Query.TrimStart('?'));
        return rp.Complete(query, request, sessionId);
    }

    static void AssertMessage(string pattern, Action call)
    {
        var err = Assert.Throws<OidcError>(call);
        Assert.True(Regex.IsMatch(err.Message, pattern), err.Message);
    }

    readonly record struct Signed(RelyingParty.Transaction Request, RelyingParty.Login Login);
}

// The SSF receiver's calls carry DPoP proofs when the relying party's token is DPoP-bound, and a
// session the receiver ends leaves the relying party's session token cache.
public class DpopSignalsTests : IClassFixture<TransmitterFixture>
{
    readonly TransmitterFixture fx;
    public DpopSignalsTests(TransmitterFixture fixture) => fx = fixture;

    [Fact]
    public void EveryTransmitterCallCarriesAProof()
    {
        using var provider = new ProviderFixture();
        provider.State.DpopAlgs = new List<object?> { "ES256" };
        var rp = RelyingParty.Create(new Dictionary<string, object?>
        {
            ["metadataUrl"] = provider.State.Url + "/.well-known/openid-configuration",
            ["clientId"] = ProviderFixture.Client,
            ["clientSecret"] = ProviderFixture.Secret,
            ["redirectUri"] = "http://127.0.0.1/callback",
            ["allowInsecure"] = true,
        });
        Assert.True(rp.UsesDpop);
        fx.Stub.DpopToken = "cc-token";
        fx.Stub.Nonce = "ssf-nonce-1";
        var ended = new List<List<string>>();
        var receiver = SignalsReceiver.New(fx.Stub.BaseUrl, (ids, _) => ended.Add(ids.ToList()))
            .WithRelyingParty(rp)
            .WithPollIntervalMs(60_000)
            .WithLog(new Quiet())
            .Build();
        receiver.Start();
        receiver.Stop();
        Assert.Equal(1, fx.Stub.Challenges);
        Assert.Empty(fx.Stub.ProofErrors);
        Assert.Equal("DPoP cc-token", fx.Stub.Authorization);
        Assert.Equal("ssf-nonce-1", rp.DpopSigner!.NonceFor(fx.Stub.BaseUrl + "/ssf/stream"));
        rp.SessionStore.Set("L-1", new SessionTokens { Subject = "urn:uuid:carol", AccessToken = "a1" });
        rp.SessionStore.Set("L-2", new SessionTokens { Subject = "urn:uuid:dave", AccessToken = "a2" });
        receiver.Track(new Dictionary<string, object?> { ["local_id"] = "L-1", ["person"] = "urn:uuid:carol", ["idp_session"] = "IDP-C1" });
        receiver.Track(new Dictionary<string, object?> { ["local_id"] = "L-2", ["person"] = "urn:uuid:dave", ["idp_session"] = "IDP-D1" });
        fx.Deliver(Events.Event["sessionRevoked"], new Dictionary<string, object?>
        {
            ["format"] = "complex",
            ["user"] = new Dictionary<string, object?> { ["format"] = "iss_sub", ["iss"] = fx.Stub.BaseUrl, ["sub"] = "urn:uuid:carol" },
            ["session"] = new Dictionary<string, object?> { ["format"] = "opaque", ["id"] = "IDP-C1" },
        }, null, fx.Signing);
        receiver.PollOnce();
        Assert.Equal(new[] { "L-1" }, ended.Single());
        Assert.Null(rp.SessionStore.Get("L-1"));
        Assert.NotNull(rp.SessionStore.Get("L-2"));
        receiver.Untrack("L-2");
        Assert.Null(rp.SessionStore.Get("L-2"));
        receiver.Verify("dpop");
        Assert.Equal("dpop", fx.Stub.VerifyState);
        Assert.Empty(fx.Stub.ProofErrors);
        Assert.Equal(1, fx.Stub.Challenges);
        Assert.True(fx.Stub.Proofs >= 5, "proofs accepted: " + fx.Stub.Proofs);
        Assert.Equal(new[] { "client_credentials" }, provider.State.TokenProofs);
    }

    sealed class Quiet : SignalsReceiver.Log
    {
        public void Info(string message) { }
        public void Warn(string message) { }
        public void Error(string message) { }
    }
}
