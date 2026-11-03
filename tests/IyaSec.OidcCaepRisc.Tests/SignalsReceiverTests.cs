// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Net;
using System.Security.Cryptography;
using System.Text;
using IyaSec.Oidc;
using Xunit;

namespace IyaSec.OidcCaepRisc.Tests;

public sealed class TransmitterFixture : IDisposable
{
    public RSA Signing { get; } = RSA.Create(2048);
    public RSA Other { get; } = RSA.Create(2048);
    public Dictionary<string, object?> Jwk { get; }
    public Transmitter Stub { get; } = new();
    readonly HttpListener listener = new();
    readonly CancellationTokenSource stop = new();

    public TransmitterFixture()
    {
        Jwk = ProviderFixture.Jwk(Signing, "k1");
        var port = ProviderFixture.FreePort();
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        listener.Start();
        Stub.BaseUrl = $"http://127.0.0.1:{port}";
        _ = Task.Run(Accept);
    }

    public void Dispose()
    {
        stop.Cancel();
        listener.Close();
        Signing.Dispose();
        Other.Dispose();
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

    void Handle(HttpListenerContext exchange)
    {
        using var reader = new StreamReader(exchange.Request.InputStream, exchange.Request.ContentEncoding);
        var text = reader.ReadToEnd();
        Stub.Authorization = exchange.Request.Headers["Authorization"] ?? "";
        var path = exchange.Request.Url!.AbsolutePath;
        if (Stub.DpopToken != null)
        {
            // DPoP mode: every call, discovery and keys included, must carry the DPoP-bound token
            // and a proof for this method and URL with ath; Nonce, when set, must be in the proof.
            var proof = exchange.Request.Headers["DPoP"];
            var check = proof == null ? null : DpopProof.Check(proof, exchange.Request.HttpMethod, Stub.BaseUrl + path, Stub.DpopToken);
            if (Stub.Authorization != "DPoP " + Stub.DpopToken || check == null || check.Error != null)
            {
                lock (Stub.ProofErrors) Stub.ProofErrors.Add(path + ": " + (check?.Error ?? "no proof or wrong scheme: " + Stub.Authorization));
                ProviderFixture.Json(exchange, 401, new Dictionary<string, object?> { ["error"] = "invalid_token" });
                return;
            }
            if (Stub.Nonce != null && check.Nonce != Stub.Nonce)
            {
                Interlocked.Increment(ref Stub.Challenges);
                exchange.Response.AddHeader("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\"");
                exchange.Response.AddHeader("DPoP-Nonce", Stub.Nonce);
                ProviderFixture.Json(exchange, 401, new Dictionary<string, object?> { ["error"] = "use_dpop_nonce" });
                return;
            }
            Interlocked.Increment(ref Stub.Proofs);
        }
        else if (Stub.Authorization != "Bearer app-token" && path != "/.well-known/ssf-configuration" && !path.StartsWith("/jwks", StringComparison.Ordinal))
        {
            ProviderFixture.Json(exchange, 401, new Dictionary<string, object?> { ["error"] = "invalid_token" });
            return;
        }
        var baseUrl = Stub.BaseUrl;
        if (path == "/.well-known/ssf-configuration")
        {
            ProviderFixture.Json(exchange, 200, new Dictionary<string, object?>
            {
                ["issuer"] = baseUrl, ["jwks_uri"] = baseUrl + "/jwks",
                ["configuration_endpoint"] = baseUrl + "/ssf/stream", ["verification_endpoint"] = baseUrl + "/ssf/verify",
                ["delivery_methods_supported"] = new List<object?> { "urn:ietf:rfc:8936" },
            });
            return;
        }
        if (path == "/jwks")
        {
            ProviderFixture.Json(exchange, 200, new Dictionary<string, object?> { ["keys"] = new List<object?> { Jwk } });
            return;
        }
        if (path == "/ssf/stream" && exchange.Request.HttpMethod == "GET")
        {
            ProviderFixture.Json(exchange, 200, Stub.Streams);
            return;
        }
        if (path == "/ssf/stream" && exchange.Request.HttpMethod == "POST")
        {
            var body = Jsons.Map(Jsons.Read(text))!;
            Stub.Created += 1;
            var asked = (Dictionary<string, object?>)body["delivery"]!;
            var delivery = new Dictionary<string, object?> { ["method"] = asked["method"], ["endpoint_url"] = baseUrl + "/ssf/poll/s" + Stub.Created };
            var stream = new Dictionary<string, object?>
            {
                ["stream_id"] = "s" + Stub.Created, ["iss"] = baseUrl, ["aud"] = "my-app", ["delivery"] = delivery,
                ["events_requested"] = body["events_requested"], ["events_delivered"] = body["events_requested"],
            };
            Stub.Streams.Add(stream);
            ProviderFixture.Json(exchange, 201, stream);
            return;
        }
        if (path == "/ssf/verify")
        {
            var body = string.IsNullOrEmpty(text) ? null : Jsons.Map(Jsons.Read(text));
            Stub.VerifyState = body?.GetValueOrDefault("state") as string ?? "";
            Stub.VerifyStatus = 204;
            exchange.Response.StatusCode = 204;
            exchange.Response.ContentLength64 = 0;
            exchange.Response.Close();
            return;
        }
        if (path.StartsWith("/ssf/poll/", StringComparison.Ordinal))
        {
            var body = string.IsNullOrEmpty(text) ? new Dictionary<string, object?>() : Jsons.Map(Jsons.Read(text))!;
            if (Jsons.List(body.GetValueOrDefault("ack")) is { } ack)
            {
                foreach (var jti in ack)
                {
                    Stub.Acked.Add(Convert.ToString(jti)!);
                    lock (Stub.Queue) Stub.Queue.Remove(Convert.ToString(jti)!);
                }
            }
            if (Jsons.Map(body.GetValueOrDefault("setErrs")) is { } errs)
            {
                foreach (var entry in errs)
                {
                    Stub.Errs[entry.Key] = entry.Value!;
                    lock (Stub.Queue) Stub.Queue.Remove(entry.Key);
                }
            }
            Dictionary<string, object?> sets;
            lock (Stub.Queue) sets = new Dictionary<string, object?>(Stub.Queue.Select(pair => new KeyValuePair<string, object?>(pair.Key, pair.Value)));
            ProviderFixture.Json(exchange, 200, new Dictionary<string, object?> { ["sets"] = sets, ["moreAvailable"] = false });
            return;
        }
        ProviderFixture.Json(exchange, 404, new Dictionary<string, object?> { ["error"] = "not_found" });
    }

    public string Jws(Dictionary<string, object?> payload, RSA key, Dictionary<string, object?>? header)
    {
        var actual = header ?? new Dictionary<string, object?> { ["alg"] = "RS256", ["kid"] = "k1", ["typ"] = "secevent+jwt" };
        var h = Codec.B64UrlEncode(Encoding.UTF8.GetBytes(Jsons.Write(actual)));
        var p = Codec.B64UrlEncode(Encoding.UTF8.GetBytes(Jsons.Write(payload)));
        if (Equals(actual.GetValueOrDefault("alg"), "none")) return h + "." + p + "." + Codec.B64UrlEncode(new byte[] { 1 });
        var signature = key.SignData(Encoding.ASCII.GetBytes(h + "." + p), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return h + "." + p + "." + Codec.B64UrlEncode(signature);
    }

    public string Deliver(string eventType, Dictionary<string, object?> subId, Dictionary<string, object?>? extra, RSA key)
    {
        var jti = Guid.NewGuid().ToString();
        var payload = new Dictionary<string, object?>
        {
            ["iss"] = Stub.BaseUrl, ["aud"] = "my-app", ["jti"] = jti,
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), ["sub_id"] = subId,
        };
        var body = new Dictionary<string, object?> { ["event_timestamp"] = 1 };
        if (extra != null) foreach (var entry in extra) body[entry.Key] = entry.Value;
        payload["events"] = new Dictionary<string, object?> { [eventType] = body };
        lock (Stub.Queue) Stub.Queue[jti] = Jws(payload, key, null);
        return jti;
    }

    public sealed class Transmitter
    {
        public string BaseUrl = "";
        public string Authorization = "";
        public int Created;
        public readonly Dictionary<string, string> Queue = new();
        public readonly List<string> Acked = new();
        public readonly Dictionary<string, object> Errs = new();
        public readonly List<Dictionary<string, object?>> Streams = new();
        public string VerifyState = "";
        public int VerifyStatus;
        public string? DpopToken;
        public string? Nonce;
        public int Challenges;
        public int Proofs;
        public readonly List<string> ProofErrors = new();
    }
}

public class SignalsReceiverTests : IClassFixture<TransmitterFixture>
{
    readonly TransmitterFixture fx;
    public SignalsReceiverTests(TransmitterFixture fixture) => fx = fixture;

    [Fact]
    public void VerifiesASetAgainstTheJwks()
    {
        var verified = SecEvent.VerifyCompactJws(fx.Jws(new Dictionary<string, object?> { ["a"] = 1 }, fx.Signing, null), new List<Dictionary<string, object?>> { fx.Jwk });
        var payload = (Dictionary<string, object?>)verified["payload"]!;
        Assert.Equal(1, Convert.ToInt32(payload["a"]));
        var mismatch = Assert.Throws<OidcError>(() => SecEvent.VerifyCompactJws(fx.Jws(new Dictionary<string, object?> { ["a"] = 1 }, fx.Other, null), new List<Dictionary<string, object?>> { fx.Jwk }));
        Assert.Contains("does not verify", mismatch.Message);
        var kid = Assert.Throws<OidcError>(() => SecEvent.VerifyCompactJws(fx.Jws(new Dictionary<string, object?> { ["a"] = 1 }, fx.Signing, new Dictionary<string, object?> { ["alg"] = "RS256", ["kid"] = "nope" }), new List<Dictionary<string, object?>> { fx.Jwk }));
        Assert.Contains("kid nope", kid.Message);
        var none = Assert.Throws<OidcError>(() => SecEvent.VerifyCompactJws(fx.Jws(new Dictionary<string, object?> { ["a"] = 1 }, fx.Signing, new Dictionary<string, object?> { ["alg"] = "none" }), new List<Dictionary<string, object?>> { fx.Jwk }));
        Assert.Contains("does not verify", none.Message);
    }

    [Fact]
    public void ReadsSubjectForms()
    {
        Assert.Equal("https://schemas.openid.net/secevent/caep/event-type/session-revoked", Events.Event["sessionRevoked"]);
        Assert.Equal("https://schemas.openid.net/secevent/risc/event-type/credential-compromise", Events.Event["credentialCompromise"]);
        var complex = new Dictionary<string, object?>
        {
            ["format"] = "complex",
            ["user"] = new Dictionary<string, object?> { ["format"] = "iss_sub", ["iss"] = "https://i", ["sub"] = "urn:uuid:a" },
            ["session"] = new Dictionary<string, object?> { ["format"] = "opaque", ["id"] = "S1" },
        };
        var parsed = Events.SubjectOf(complex, "https://i");
        Assert.Equal("urn:uuid:a", parsed["person"]);
        Assert.Equal("S1", parsed["idpSession"]);
        Assert.Empty(Events.SubjectOf(new Dictionary<string, object?> { ["format"] = "iss_sub", ["iss"] = "https://other", ["sub"] = "urn:uuid:a" }, "https://i"));
        Assert.Equal("A@x.com", Events.SubjectOf(new Dictionary<string, object?> { ["format"] = "email", ["email"] = "A@x.com" }, "https://i")["email"]);
    }

    [Fact]
    public void PollsAndEndsOnlyTheNamedSession()
    {
        var ended = new List<List<string>>();
        var seen = new List<Dictionary<string, object?>>();
        var receiver = SignalsReceiver.New(fx.Stub.BaseUrl, (ids, _) => ended.Add(ids.ToList()))
            .WithHeaders(() => new Dictionary<string, string> { ["authorization"] = "Bearer app-token" })
            .WithPollIntervalMs(60_000)
            .WithLog(new Quiet())
            .Build();
        receiver.On("*", seen.Add);
        receiver.Start();
        receiver.Stop();
        Assert.Equal(1, fx.Stub.Created);
        Assert.Equal("Bearer app-token", fx.Stub.Authorization);
        Assert.Equal("s1", receiver.Stream!["stream_id"]);
        receiver.Track(Session("L-a1", "alice", "IDP-A1"));
        receiver.Track(Session("L-a2", "alice", "IDP-A2"));
        receiver.Track(Session("L-b1", "bob", "IDP-B1"));
        var revoked = fx.Deliver(Events.Event["sessionRevoked"], Complex("alice", "IDP-A1"), null, fx.Signing);
        fx.Deliver(Events.Event["credentialChange"], new Dictionary<string, object?> { ["format"] = "iss_sub", ["iss"] = fx.Stub.BaseUrl, ["sub"] = "urn:uuid:bob" }, new Dictionary<string, object?> { ["credential_type"] = "password" }, fx.Signing);
        receiver.PollOnce();
        Assert.Equal(new[] { "L-a1" }, ended[0]);
        Assert.Single(ended);
        Assert.Equal(2, seen.Count);
        Assert.Equal(true, seen[0]["ended"]);
        Assert.Equal(Events.Event["credentialChange"], seen[1]["type"]);
        Assert.Equal(false, seen[1]["ended"]);
        receiver.PollOnce();
        var acked = fx.Stub.Acked.ToList();
        var expected = new List<string> { revoked };
        foreach (var item in acked) if (item != revoked) expected.Add(item);
        Assert.Equal(expected, acked);
        var bad = fx.Deliver(Events.Event["accountDisabled"], new Dictionary<string, object?> { ["format"] = "email", ["email"] = "alice@example.com" }, null, fx.Other);
        receiver.PollOnce();
        receiver.PollOnce();
        var problem = (Dictionary<string, object?>)fx.Stub.Errs[bad];
        Assert.Equal("invalid_key", problem["err"]);
        receiver.Verify("abc");
        Assert.Equal("abc", fx.Stub.VerifyState);
        Assert.Equal(204, fx.Stub.VerifyStatus);
        receiver.Stop();
    }

    [Fact]
    public void OidcErrorIsExported()
    {
        var err = new OidcError("config", "signals must be true or false");
        Assert.Equal("signals must be true or false", err.Message);
        Assert.Equal("config", err.Code);
    }

    static Dictionary<string, object?> Session(string localId, string person, string sid) => new()
    {
        ["local_id"] = localId, ["person"] = "urn:uuid:" + person, ["email"] = person + "@example.com", ["idp_session"] = sid,
    };

    Dictionary<string, object?> Complex(string person, string sid) => new()
    {
        ["format"] = "complex",
        ["user"] = new Dictionary<string, object?> { ["format"] = "iss_sub", ["iss"] = fx.Stub.BaseUrl, ["sub"] = "urn:uuid:" + person },
        ["session"] = new Dictionary<string, object?> { ["format"] = "opaque", ["id"] = sid },
    };

    sealed class Quiet : SignalsReceiver.Log
    {
        public void Info(string message) { }
        public void Warn(string message) { }
        public void Error(string message) { }
    }
}
