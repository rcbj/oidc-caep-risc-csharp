// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using System.Text;
using IyaSec.Oidc;

namespace IyaSec.OidcCaepRisc.Tests;

/// <summary>The stubs' check of a DPoP proof (RFC 9449 section 4.3), written apart from the library's signer.</summary>
public static class DpopProof
{
    public sealed record Result(string? Error, string Jkt, Dictionary<string, object?> Payload, string? Nonce);

    public static Result Check(string proof, string method, string htu, string? accessToken)
    {
        var empty = new Dictionary<string, object?>();
        var parts = proof.Split('.');
        if (parts.Length != 3) return new Result("not a compact JWS", "", empty, null);
        Dictionary<string, object?> header, payload;
        try
        {
            header = Jsons.Map(Jsons.Read(Encoding.UTF8.GetString(Codec.B64UrlDecode(parts[0], "header"))))!;
            payload = Jsons.Map(Jsons.Read(Encoding.UTF8.GetString(Codec.B64UrlDecode(parts[1], "payload"))))!;
        }
        catch (Exception err)
        {
            return new Result("unreadable: " + err.Message, "", empty, null);
        }
        if (!Equals(header.GetValueOrDefault("typ"), "dpop+jwt")) return new Result("typ is not dpop+jwt", "", payload, null);
        if (!Equals(header.GetValueOrDefault("alg"), "ES256")) return new Result("alg is not ES256", "", payload, null);
        var jwk = Jsons.Map(header.GetValueOrDefault("jwk"));
        if (jwk == null || !Equals(jwk.GetValueOrDefault("kty"), "EC") || !Equals(jwk.GetValueOrDefault("crv"), "P-256")) return new Result("jwk is not a P-256 key", "", payload, null);
        if (jwk.ContainsKey("d")) return new Result("jwk carries the private key", "", payload, null);
        var x = Convert.ToString(jwk["x"])!;
        var y = Convert.ToString(jwk["y"])!;
        using var key = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = Codec.B64UrlDecode(x, "x"), Y = Codec.B64UrlDecode(y, "y") },
        });
        var signature = Codec.B64UrlDecode(parts[2], "signature");
        if (!key.VerifyData(Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
        {
            return new Result("signature does not verify", "", payload, null);
        }
        if (payload.GetValueOrDefault("jti") is not string jti || jti.Length == 0) return new Result("no jti", "", payload, null);
        if (!Equals(payload.GetValueOrDefault("htm"), method)) return new Result("htm is " + payload.GetValueOrDefault("htm"), "", payload, null);
        if (!Equals(payload.GetValueOrDefault("htu"), htu)) return new Result("htu is " + payload.GetValueOrDefault("htu") + ", not " + htu, "", payload, null);
        if (payload.GetValueOrDefault("iat") is not long iat || Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - iat) > 60) return new Result("iat is not now", "", payload, null);
        if (accessToken != null)
        {
            var ath = Codec.B64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken)));
            if (!Equals(payload.GetValueOrDefault("ath"), ath)) return new Result("ath does not match the access token", "", payload, null);
        }
        else if (payload.ContainsKey("ath"))
        {
            return new Result("ath on a proof with no access token", "", payload, null);
        }
        return new Result(null, Thumbprint(x, y), payload, payload.GetValueOrDefault("nonce") as string);
    }

    public static string Thumbprint(string x, string y)
    {
        var canonical = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" + x + "\",\"y\":\"" + y + "\"}";
        return Codec.B64UrlEncode(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }
}
