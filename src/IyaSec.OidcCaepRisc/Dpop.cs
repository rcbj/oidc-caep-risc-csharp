// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace IyaSec.Oidc;

/// <summary>
/// DPoP (RFC 9449) proofs signed with one ES256 (P-256) key. The key is generated when the
/// relying party is created and held in memory only, unless the <c>dpopKey</c> setting names a
/// PEM private key (for an application that runs several processes). The latest
/// <c>DPoP-Nonce</c> each server origin gave is remembered and sent on the next proof to it.
/// </summary>
public sealed class Dpop : IDisposable
{
    /// <summary>The one proof algorithm this library signs with.</summary>
    public const string Algorithm = "ES256";

    readonly ECDsa key;
    readonly Dictionary<string, object?> jwk;
    readonly ConcurrentDictionary<string, string> nonces = new(StringComparer.Ordinal);

    /// <summary>A signer over a new P-256 key pair, or over the PEM private key given.</summary>
    /// <param name="pem">A PEM P-256 private key (PKCS#8 or SEC 1), or null to generate one.</param>
    public Dpop(string? pem = null)
    {
        if (string.IsNullOrEmpty(pem))
        {
            key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        }
        else
        {
            try
            {
                key = ECDsa.Create();
                key.ImportFromPem(pem);
            }
            catch (Exception err)
            {
                throw new OidcError("config", "dpopKey is not a PEM EC private key: " + err.Message, err);
            }
            if (key.KeySize != 256)
            {
                key.Dispose();
                throw new OidcError("config", "dpopKey must be a P-256 key (ES256)");
            }
        }
        var point = key.ExportParameters(false).Q;
        jwk = new Dictionary<string, object?>
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = Codec.B64UrlEncode(point.X!),
            ["y"] = Codec.B64UrlEncode(point.Y!),
        };
        // RFC 7638: the required members in lexicographic order, no whitespace.
        var canonical = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" + jwk["x"] + "\",\"y\":\"" + jwk["y"] + "\"}";
        Thumbprint = Codec.B64UrlEncode(Codec.Sha256(Encoding.UTF8.GetBytes(canonical)));
    }

    /// <summary>The public key as a JWK (kty, crv, x, y).</summary>
    public IReadOnlyDictionary<string, object?> PublicJwk => jwk;

    /// <summary>The RFC 7638 SHA-256 thumbprint of the public key: the value of <c>dpop_jkt</c>.</summary>
    public string Thumbprint { get; }

    /// <summary>
    /// A proof for one request: <c>typ</c> <c>dpop+jwt</c>, the public <c>jwk</c>, and
    /// <c>jti</c>, <c>htm</c>, <c>htu</c> (without query or fragment), <c>iat</c>, the origin's
    /// latest nonce when one is known, and <c>ath</c> when an access token is given.
    /// </summary>
    /// <param name="method">The HTTP method.</param>
    /// <param name="url">The request URL.</param>
    /// <param name="accessToken">The access token the request carries, for <c>ath</c>.</param>
    public string Proof(string method, string url, string? accessToken = null)
    {
        var header = new Dictionary<string, object?>
        {
            ["typ"] = "dpop+jwt",
            ["alg"] = Algorithm,
            ["jwk"] = jwk,
        };
        var payload = new Dictionary<string, object?>
        {
            ["jti"] = Codec.RandomToken(),
            ["htm"] = method.ToUpperInvariant(),
            ["htu"] = Htu(url),
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        };
        if (nonces.TryGetValue(Origin(url), out var nonce)) payload["nonce"] = nonce;
        if (!string.IsNullOrEmpty(accessToken))
        {
            payload["ath"] = Codec.B64UrlEncode(Codec.Sha256(Encoding.ASCII.GetBytes(accessToken)));
        }
        var input = Codec.B64UrlEncode(Encoding.UTF8.GetBytes(Jsons.Write(header)))
            + "." + Codec.B64UrlEncode(Encoding.UTF8.GetBytes(Jsons.Write(payload)));
        var signature = key.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return input + "." + Codec.B64UrlEncode(signature);
    }

    /// <summary>Remembers the <c>DPoP-Nonce</c> a response carried, for the next proof to that origin.</summary>
    /// <returns>True when the response carried a nonce.</returns>
    public bool Remember(string url, Http.Result answer)
    {
        var nonce = answer.Header("DPoP-Nonce");
        if (string.IsNullOrEmpty(nonce)) return false;
        nonces[Origin(url)] = nonce.Trim();
        return true;
    }

    /// <summary>The latest nonce remembered for the origin of <paramref name="url"/>, or null.</summary>
    public string? NonceFor(string url) => nonces.TryGetValue(Origin(url), out var nonce) ? nonce : null;

    /// <summary>The <c>htu</c> of a URL: scheme, authority, and path, without query or fragment.</summary>
    public static string Htu(string url)
    {
        var uri = new Uri(url);
        return uri.GetComponents(UriComponents.SchemeAndServer | UriComponents.Path, UriFormat.UriEscaped);
    }

    /// <summary>True when a resource server's 401 asks for a DPoP nonce (<c>WWW-Authenticate: DPoP error="use_dpop_nonce"</c>).</summary>
    public static bool ResourceAsksForNonce(Http.Result answer)
    {
        if (answer.Status != 401) return false;
        var challenge = answer.Header("WWW-Authenticate") ?? "";
        return System.Text.RegularExpressions.Regex.IsMatch(challenge, "(^|[\\s,])DPoP(\\s|$)", System.Text.RegularExpressions.RegexOptions.IgnoreCase)
            && System.Text.RegularExpressions.Regex.IsMatch(challenge, "error\\s*=\\s*\"?use_dpop_nonce\"?", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
    }

    static string Origin(string url)
    {
        var uri = new Uri(url);
        return uri.GetComponents(UriComponents.SchemeAndServer, UriFormat.UriEscaped).ToLowerInvariant();
    }

    /// <summary>Releases the key.</summary>
    public void Dispose() => key.Dispose();
}
