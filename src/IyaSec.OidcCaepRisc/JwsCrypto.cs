// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using System.Text;

namespace IyaSec.Oidc;

/// <summary>JWS sign and verify. HMAC is used only when an ID token names it. EdDSA is not available in this runtime.</summary>
public static class JwsCrypto
{
    public static readonly IReadOnlyList<string> Supported = new[]
    {
        "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
        "ES256", "ES384", "ES512", "EdDSA", "Ed25519",
    };

    static readonly Dictionary<string, string[]> Algs = new()
    {
        ["RS256"] = new[] { "RSA", "SHA-256", "pkcs1" },
        ["RS384"] = new[] { "RSA", "SHA-384", "pkcs1" },
        ["RS512"] = new[] { "RSA", "SHA-512", "pkcs1" },
        ["PS256"] = new[] { "RSA", "SHA-256", "pss" },
        ["PS384"] = new[] { "RSA", "SHA-384", "pss" },
        ["PS512"] = new[] { "RSA", "SHA-512", "pss" },
        ["ES256"] = new[] { "EC", "SHA-256", "p1363" },
        ["ES384"] = new[] { "EC", "SHA-384", "p1363" },
        ["ES512"] = new[] { "EC", "SHA-512", "p1363" },
        ["EdDSA"] = new[] { "OKP", "", "eddsa" },
        ["Ed25519"] = new[] { "OKP", "", "eddsa" },
        ["HS256"] = new[] { "oct", "SHA-256", "hmac" },
        ["HS384"] = new[] { "oct", "SHA-384", "hmac" },
        ["HS512"] = new[] { "oct", "SHA-512", "hmac" },
    };

    public static string[]? Alg(string? name) => name != null && Algs.TryGetValue(name, out var spec) ? spec : null;

    public sealed class Material : IDisposable
    {
        public RSA? Rsa { get; }
        public ECDsa? Ec { get; }
        public string Kind { get; }

        public Material(RSA? rsa, ECDsa? ec, string kind)
        {
            Rsa = rsa;
            Ec = ec;
            Kind = kind;
        }

        public void Dispose()
        {
            Rsa?.Dispose();
            Ec?.Dispose();
        }
    }

    public static Material PublicKey(IReadOnlyDictionary<string, object?> jwk)
    {
        try
        {
            var kty = AsString(jwk, "kty");
            if (kty == "RSA")
            {
                var rsa = RSA.Create();
                rsa.ImportParameters(new RSAParameters
                {
                    Modulus = Unsigned(Codec.B64UrlDecode(AsString(jwk, "n") ?? "", "n")),
                    Exponent = Unsigned(Codec.B64UrlDecode(AsString(jwk, "e") ?? "", "e")),
                });
                return new Material(rsa, null, "RSA");
            }
            if (kty == "EC")
            {
                var curveName = AsString(jwk, "crv") ?? "";
                var curve = curveName switch
                {
                    "P-256" => ECCurve.NamedCurves.nistP256,
                    "P-384" => ECCurve.NamedCurves.nistP384,
                    "P-521" => ECCurve.NamedCurves.nistP521,
                    _ => throw new ArgumentException(curveName),
                };
                int size = curveName == "P-521" ? 66 : curveName == "P-384" ? 48 : 32;
                var x = Codec.B64UrlDecode(AsString(jwk, "x") ?? "", "x");
                var y = Codec.B64UrlDecode(AsString(jwk, "y") ?? "", "y");
                if (x.Length != size || y.Length != size) throw new ArgumentException("EC coordinate length");
                var ec = ECDsa.Create(new ECParameters { Curve = curve, Q = new ECPoint { X = x, Y = y } });
                return new Material(null, ec, "EC");
            }
        }
        catch (OidcError)
        {
            throw;
        }
        catch (Exception err)
        {
            var kid = jwk.TryGetValue("kid", out var id) ? id : null;
            throw new OidcError("signature", "the transmitter's key " + (kid ?? "") + " cannot be read: " + err.Message, err);
        }
        var kind = jwk.TryGetValue("kty", out var named) ? named : null;
        throw new OidcError("signature", "the key type " + kind + " cannot be read");
    }

    public static Material LoadPrivateKey(string pem, string alg)
    {
        if (!Algs.TryGetValue(alg, out var spec))
        {
            throw new OidcError("config", "the private key could not be read as " + alg + ": unsupported algorithm");
        }
        if (spec[0] == "OKP")
        {
            throw new OidcError("config", "the private key could not be read as " + alg + ": Ed25519 is not available in this runtime");
        }
        Material key;
        try
        {
            if (spec[0] == "RSA")
            {
                var rsa = RSA.Create();
                rsa.ImportFromPem(pem);
                key = new Material(rsa, null, "RSA");
            }
            else
            {
                var ec = ECDsa.Create();
                ec.ImportFromPem(pem);
                key = new Material(null, ec, "EC");
            }
        }
        catch (Exception err)
        {
            throw new OidcError("config", "the private key could not be read as " + alg + ": " + err.Message, err);
        }
        if (spec[0] == "EC" && key.Ec != null)
        {
            int field = key.Ec.KeySize;
            var expected = field == 256 ? "ES256" : field == 384 ? "ES384" : field == 521 ? "ES512" : "";
            if (expected != alg)
            {
                key.Dispose();
                throw new OidcError("config", "the private key could not be read as " + alg + ": key type does not match " + alg);
            }
        }
        return key;
    }

    public static string SignCompact(IDictionary<string, object?> header, IDictionary<string, object?> payload, Material key, string alg)
    {
        try
        {
            var signingInput = Codec.B64UrlEncode(Encoding.UTF8.GetBytes(Jsons.Write(header)))
                + "." + Codec.B64UrlEncode(Encoding.UTF8.GetBytes(Jsons.Write(payload)));
            var signature = Sign(key, alg, Encoding.ASCII.GetBytes(signingInput));
            return signingInput + "." + Codec.B64UrlEncode(signature);
        }
        catch (OidcError)
        {
            throw;
        }
        catch (Exception err)
        {
            throw new OidcError("protocol", "the client assertion could not be signed: " + err.Message, err);
        }
    }

    public static byte[] Sign(Material key, string alg, byte[] input)
    {
        var spec = Algs[alg];
        try
        {
            if (spec[2] == "eddsa") throw new OidcError("protocol", "the client assertion could not be signed: Ed25519 is not available in this runtime");
            if (spec[0] == "RSA" && key.Rsa != null)
            {
                return key.Rsa.SignData(input, Hash(spec[1]), spec[2] == "pss" ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1);
            }
            if (spec[0] == "EC" && key.Ec != null)
            {
                return key.Ec.SignData(input, Hash(spec[1]), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }
            throw new OidcError("protocol", "the client assertion could not be signed: key type does not match " + alg);
        }
        catch (OidcError)
        {
            throw;
        }
        catch (Exception err)
        {
            throw new OidcError("protocol", "the client assertion could not be signed: " + err.Message, err);
        }
    }

    public static bool Verify(Material key, string alg, byte[] input, byte[] signature)
    {
        if (!Algs.TryGetValue(alg, out var spec) || spec[2] == "hmac" || spec[2] == "eddsa") return false;
        try
        {
            if (spec[0] == "RSA" && key.Rsa != null)
            {
                return key.Rsa.VerifyData(input, signature, Hash(spec[1]), spec[2] == "pss" ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1);
            }
            if (spec[0] == "EC" && key.Ec != null)
            {
                return key.Ec.VerifyData(input, signature, Hash(spec[1]), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }
            return false;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    public static bool VerifyHmac(byte[] secret, string alg, byte[] input, byte[] signature)
    {
        if (!Algs.TryGetValue(alg, out var spec) || spec[2] != "hmac") return false;
        try
        {
            var mac = spec[1] switch
            {
                "SHA-384" => HMACSHA384.HashData(secret, input),
                "SHA-512" => HMACSHA512.HashData(secret, input),
                _ => HMACSHA256.HashData(secret, input),
            };
            return CryptographicOperations.FixedTimeEquals(mac, signature);
        }
        catch (Exception)
        {
            return false;
        }
    }

    static HashAlgorithmName Hash(string name) => name switch
    {
        "SHA-384" => HashAlgorithmName.SHA384,
        "SHA-512" => HashAlgorithmName.SHA512,
        _ => HashAlgorithmName.SHA256,
    };

    static byte[] Unsigned(byte[] raw) => raw.Length > 1 && raw[0] == 0 ? raw[1..] : raw;

    static string? AsString(IReadOnlyDictionary<string, object?> map, string name)
    {
        return map.TryGetValue(name, out var value) && value is string text ? text : null;
    }
}
