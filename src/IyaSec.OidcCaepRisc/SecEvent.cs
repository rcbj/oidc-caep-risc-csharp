// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Text;

namespace IyaSec.Oidc;

/// <summary>Verify a Security Event Token. The key comes from the JWKS, never from the token.</summary>
public static class SecEvent
{
    public static Dictionary<string, object?> VerifyCompactJws(string? token, IReadOnlyList<Dictionary<string, object?>> keys)
    {
        var parts = token == null ? Array.Empty<string>() : token.Split('.');
        if (parts.Length != 3 || parts[0].Length == 0 || parts[1].Length == 0 || parts[2].Length == 0)
        {
            throw new OidcError("signature", "the SET is not a compact JWS");
        }
        Dictionary<string, object?>? header;
        Dictionary<string, object?>? payload;
        try
        {
            header = Object(parts[0], "header");
            payload = Object(parts[1], "payload");
        }
        catch (OidcError)
        {
            throw;
        }
        catch (ArgumentException err)
        {
            var message = err.Message ?? "";
            if (message.Contains("base64url", StringComparison.Ordinal))
            {
                var what = message.Contains("header", StringComparison.Ordinal) ? "header" : message.Contains("payload", StringComparison.Ordinal) ? "payload" : "signature";
                throw new OidcError("signature", "the SET's " + what + " is not base64url", err);
            }
            throw new OidcError("signature", "the SET's header or payload is not JSON", err);
        }
        if (header == null || payload == null) throw new OidcError("signature", "the SET's header or payload is not a JSON object");
        var alg = header.GetValueOrDefault("alg") == null ? "" : Convert.ToString(header["alg"])!;
        var spec = JwsCrypto.Alg(alg);
        if (spec == null || spec[2] == "hmac")
        {
            throw new OidcError("signature", "the SET is signed with " + (alg.Length == 0 ? "(no alg)" : alg) + ", which this receiver does not verify (" + string.Join(", ", JwsCrypto.Supported) + ")");
        }
        if (header.ContainsKey("crit") && header["crit"] != null)
        {
            throw new OidcError("signature", "the SET's header has a crit member this receiver does not understand");
        }
        var kid = header.GetValueOrDefault("kid") as string;
        var candidates = new List<Dictionary<string, object?>>();
        foreach (var jwk in keys)
        {
            var kidOk = kid == null || kid.Equals(jwk.GetValueOrDefault("kid"));
            var useOk = jwk.GetValueOrDefault("use") == null || Equals(jwk["use"], "sig");
            var algOk = jwk.GetValueOrDefault("alg") == null || Equals(jwk["alg"], alg);
            if (kidOk && spec[0].Equals(jwk.GetValueOrDefault("kty")) && useOk && algOk) candidates.Add(jwk);
        }
        if (candidates.Count == 0)
        {
            var suffix = kid == null ? "" : " with kid " + kid;
            throw new OidcError("signature", "the transmitter publishes no " + spec[0] + " signing key" + suffix);
        }
        byte[] signature;
        try
        {
            signature = Codec.B64UrlDecode(parts[2], "signature");
        }
        catch (Exception err)
        {
            throw new OidcError("signature", "the SET's signature is not base64url", err);
        }
        var data = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
        foreach (var jwk in candidates)
        {
            using var key = JwsCrypto.PublicKey(jwk);
            if (JwsCrypto.Verify(key, alg, data, signature))
            {
                return new Dictionary<string, object?> { ["header"] = header, ["payload"] = payload };
            }
        }
        throw new OidcError("signature", "the SET's signature does not verify against the transmitter's keys");
    }

    static Dictionary<string, object?>? Object(string part, string what)
    {
        var parsed = Jsons.Read(Encoding.UTF8.GetString(Codec.B64UrlDecode(part, what)));
        return Jsons.Map(parsed);
    }
}
