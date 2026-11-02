// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using System.Text;

namespace IyaSec.Oidc;

/// <summary>ID token checks: signature, issuer, audience, time, nonce, and at_hash / c_hash.</summary>
public static class IdToken
{
    static readonly HashSet<string> NotIdToken = new(StringComparer.Ordinal)
    {
        "at+jwt", "application/at+jwt", "logout+jwt", "secevent+jwt", "dpop+jwt",
        "token-introspection+jwt", "software-statement+jwt", "jwt-bearer",
    };

    public static string HashClaim(string value, string alg)
    {
        var name = alg is "EdDSA" or "Ed25519" ? "SHA-512" : alg != null && alg.Contains("384", StringComparison.Ordinal) ? "SHA-384" : alg != null && alg.Contains("512", StringComparison.Ordinal) ? "SHA-512" : "SHA-256";
        var digest = name switch
        {
            "SHA-384" => Codec.Sha384(Encoding.UTF8.GetBytes(value)),
            "SHA-512" => Codec.Sha512(Encoding.UTF8.GetBytes(value)),
            _ => Codec.Sha256(Encoding.UTF8.GetBytes(value)),
        };
        return Codec.B64UrlEncode(digest[..(digest.Length / 2)]);
    }

    public static Dictionary<string, object?> Validate(string token, IReadOnlyDictionary<string, object?> checks)
    {
        var header = Part(token, 0);
        var alg = header.GetValueOrDefault("alg") == null ? "" : Convert.ToString(header["alg"])!;
        var algorithms = Strings(checks.GetValueOrDefault("algorithms"));
        if (!algorithms.Contains(alg))
        {
            throw new OidcError("signature", "the ID token is signed with " + (alg.Length == 0 ? "(no alg)" : alg) + ", which this client does not accept");
        }
        if (header.ContainsKey("crit") && header["crit"] != null)
        {
            throw new OidcError("validation", "the ID token has a crit header this client does not understand");
        }
        var typ = header.GetValueOrDefault("typ") == null ? "" : Convert.ToString(header["typ"])!.ToLowerInvariant();
        if (typ.Length > 0 && ((typ != "jwt" && typ != "application/jwt") || NotIdToken.Contains(typ)))
        {
            throw new OidcError("validation", "the ID token typ is " + header["typ"] + ", not an ID token");
        }
        if (alg.StartsWith("HS", StringComparison.Ordinal) && string.IsNullOrEmpty(Convert.ToString(checks.GetValueOrDefault("clientSecret"))))
        {
            throw new OidcError("config", alg + " ID tokens need the client secret");
        }
        var payload = Part(token, 1);
        bool ok;
        try
        {
            ok = SignatureOk(token, alg, Maps(checks.GetValueOrDefault("jwks")), checks.GetValueOrDefault("clientSecret") == null ? "" : Convert.ToString(checks["clientSecret"])!);
        }
        catch (OidcError)
        {
            throw;
        }
        catch (Exception err)
        {
            throw new OidcError("signature", "the ID token was refused: signature: " + err.Message, err);
        }
        if (!ok) throw new OidcError("signature", "the ID token was refused: signature verification failed");
        if (Convert.ToString(checks.GetValueOrDefault("issuer")) != Convert.ToString(payload.GetValueOrDefault("iss")))
        {
            throw new OidcError("validation", "the ID token was refused: issuer mismatch");
        }
        var audiences = Audiences(payload.GetValueOrDefault("aud"));
        if (!audiences.Contains(Convert.ToString(checks.GetValueOrDefault("clientId"))))
        {
            throw new OidcError("validation", "the ID token audience does not include this client");
        }
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0;
        var tolerance = Number(checks.GetValueOrDefault("clockToleranceSec")) ?? 0;
        if (Number(payload.GetValueOrDefault("exp")) is not double exp) throw new OidcError("validation", "the ID token was refused: exp is missing");
        if (exp + tolerance < now) throw new OidcError("validation", "the ID token was refused: exp expired");
        if (Number(payload.GetValueOrDefault("nbf")) is double nbf && nbf - tolerance > now)
        {
            throw new OidcError("validation", "the ID token was refused: nbf is in the future");
        }
        if (checks.ContainsKey("maxIdTokenAgeSec") && checks.GetValueOrDefault("maxIdTokenAgeSec") != null)
        {
            if (Number(payload.GetValueOrDefault("iat")) is not double iat) throw new OidcError("validation", "the ID token was refused: iat is missing");
            var maxAge = Number(checks["maxIdTokenAgeSec"]) ?? 0;
            if ((now - iat) - tolerance > maxAge) throw new OidcError("validation", "the ID token was refused: iat is too old");
        }
        if (payload.GetValueOrDefault("sub") is not string sub || sub.Length == 0) throw new OidcError("validation", "the ID token has no sub");
        if (audiences.Count > 1 && Convert.ToString(checks.GetValueOrDefault("clientId")) != Convert.ToString(payload.GetValueOrDefault("azp")))
        {
            throw new OidcError("validation", "an ID token with several audiences must name this client as azp");
        }
        if (payload.ContainsKey("azp") && payload["azp"] != null && Convert.ToString(checks.GetValueOrDefault("clientId")) != Convert.ToString(payload["azp"]))
        {
            throw new OidcError("validation", "the ID token azp is " + payload["azp"] + ", not " + checks.GetValueOrDefault("clientId"));
        }
        if (checks.ContainsKey("nonce") && checks.GetValueOrDefault("nonce") != null)
        {
            if (payload.GetValueOrDefault("nonce") is not string nonce || !Same(nonce, Convert.ToString(checks["nonce"])!))
            {
                throw new OidcError("validation", "the ID token nonce does not match this sign-in");
            }
        }
        if (checks.ContainsKey("previousSub") && checks.GetValueOrDefault("previousSub") != null && Convert.ToString(checks["previousSub"]) != Convert.ToString(payload.GetValueOrDefault("sub")))
        {
            throw new OidcError("validation", "the refreshed ID token is for a different subject");
        }
        if (Config.Truthy(checks.GetValueOrDefault("accessToken"))) CheckHash(payload.GetValueOrDefault("at_hash"), Convert.ToString(checks["accessToken"])!, alg, "at_hash");
        if (Config.Truthy(checks.GetValueOrDefault("code"))) CheckHash(payload.GetValueOrDefault("c_hash"), Convert.ToString(checks["code"])!, alg, "c_hash");
        if (checks.ContainsKey("maxAge") && checks.GetValueOrDefault("maxAge") != null)
        {
            if (Number(payload.GetValueOrDefault("auth_time")) is not double authTime)
            {
                throw new OidcError("validation", "max_age was requested and the ID token has no auth_time");
            }
            var maxAge = (long)(Number(checks["maxAge"]) ?? 0);
            if (authTime < (DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0) - maxAge - tolerance)
            {
                throw new OidcError("validation", "the ID token auth_time is older than max_age");
            }
        }
        return payload;
    }

    public static List<Dictionary<string, object?>> FetchJwks(string jwksUri, IReadOnlyDictionary<string, string>? tls)
    {
        var answer = Http.Send(jwksUri, "GET", new Dictionary<string, string> { ["accept"] = "application/json" }, null, tls, "discovery");
        if (answer.Status != 200) throw new OidcError("discovery", "the JWKS at " + jwksUri + " answered " + answer.Status);
        object? body;
        try
        {
            body = Jsons.Read(answer.Body);
        }
        catch (Exception err)
        {
            throw new OidcError("discovery", "the JWKS at " + jwksUri + " is not JSON", err);
        }
        var doc = Jsons.Map(body);
        var keys = doc == null ? null : Jsons.List(doc.GetValueOrDefault("keys"));
        if (doc == null || keys == null) throw new OidcError("discovery", "the JWKS at " + jwksUri + " has no keys");
        var output = new List<Dictionary<string, object?>>();
        foreach (var key in keys)
        {
            var jwk = Jsons.Map(key);
            if (jwk != null) output.Add(jwk);
        }
        return output;
    }

    static void CheckHash(object? claim, string value, string alg, string name)
    {
        if (claim == null) return;
        if (claim is not string text || !Same(text, HashClaim(value, alg)))
        {
            throw new OidcError("validation", "the ID token's " + name + " does not match");
        }
    }

    static bool SignatureOk(string token, string alg, List<Dictionary<string, object?>> jwks, string secret)
    {
        var parts = token.Split('.');
        var input = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
        byte[] signature;
        try
        {
            signature = Codec.B64UrlDecode(parts[2], "signature");
        }
        catch (Exception err)
        {
            throw new OidcError("signature", "the ID token is not a compact JWS: " + err.Message, err);
        }
        if (alg.StartsWith("HS", StringComparison.Ordinal)) return JwsCrypto.VerifyHmac(Encoding.UTF8.GetBytes(secret), alg, input, signature);
        var header = Part(token, 0);
        var kid = header.GetValueOrDefault("kid") as string;
        var keys = Candidates(jwks, alg, kid);
        if (keys.Count == 0) throw new OidcError("signature", "signature verification failed: no applicable key");
        foreach (var jwk in keys)
        {
            JwsCrypto.Material key;
            try
            {
                key = JwsCrypto.PublicKey(jwk);
            }
            catch (OidcError)
            {
                continue;
            }
            using (key)
            {
                if (JwsCrypto.Verify(key, alg, input, signature)) return true;
            }
        }
        return false;
    }

    static List<Dictionary<string, object?>> Candidates(List<Dictionary<string, object?>> jwks, string alg, string? kid)
    {
        var spec = JwsCrypto.Alg(alg);
        var found = new List<Dictionary<string, object?>>();
        if (spec == null) return found;
        foreach (var jwk in jwks)
        {
            if (kid != null && !kid.Equals(jwk.GetValueOrDefault("kid"))) continue;
            if (!spec[0].Equals(jwk.GetValueOrDefault("kty"))) continue;
            if (jwk.GetValueOrDefault("use") != null && !Equals(jwk["use"], "sig")) continue;
            if (jwk.GetValueOrDefault("alg") != null && !Equals(jwk["alg"], alg)) continue;
            found.Add(jwk);
        }
        return found;
    }

    static Dictionary<string, object?> Part(string? token, int index)
    {
        var parts = token == null ? Array.Empty<string>() : token.Split('.');
        if (parts.Length != 3 || parts[0].Length == 0 || parts[1].Length == 0 || parts[2].Length == 0)
        {
            throw new OidcError("signature", "the ID token is not a compact JWS: not a compact JWS");
        }
        try
        {
            var parsed = Jsons.Read(Encoding.UTF8.GetString(Codec.B64UrlDecode(parts[index], index == 0 ? "header" : "payload")));
            return Jsons.Map(parsed) ?? throw new OidcError("signature", "the ID token is not a compact JWS: not a JSON object");
        }
        catch (OidcError)
        {
            throw;
        }
        catch (Exception err)
        {
            throw new OidcError("signature", "the ID token is not a compact JWS: " + err.Message, err);
        }
    }

    static List<string> Audiences(object? aud)
    {
        if (Jsons.List(aud) is { } items) return items.Select(item => Convert.ToString(item) ?? "").ToList();
        return new List<string> { aud == null ? "" : Convert.ToString(aud)! };
    }

    static List<string> Strings(object? value)
    {
        var output = new List<string>();
        if (Jsons.List(value) is { } items) foreach (var item in items) output.Add(Convert.ToString(item) ?? "");
        return output;
    }

    static List<Dictionary<string, object?>> Maps(object? value)
    {
        var output = new List<Dictionary<string, object?>>();
        if (Jsons.List(value) is { } items)
        {
            foreach (var item in items)
            {
                var map = Jsons.Map(item);
                if (map != null) output.Add(map);
            }
        }
        return output;
    }

    static bool Same(string left, string right)
    {
        var a = Encoding.UTF8.GetBytes(left);
        var b = Encoding.UTF8.GetBytes(right);
        return a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    }

    static double? Number(object? value) => value is byte or short or int or long or float or double or decimal ? Config.AsDouble(value) : null;
}
