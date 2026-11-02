// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Text;

namespace IyaSec.Oidc;

/// <summary>Client authentication on a token or pushed-authorization request.</summary>
public static class ClientAuth
{
    public static void Apply(IReadOnlyDictionary<string, object?> config, JwsCrypto.Material? key, IDictionary<string, object?> body, IDictionary<string, string> headers, string audience)
    {
        var method = Convert.ToString(config["tokenEndpointAuthMethod"]);
        var clientId = Convert.ToString(config["clientId"])!;
        if (method == "client_secret_basic")
        {
            var secret = config.GetValueOrDefault("clientSecret") == null ? "" : Convert.ToString(config["clientSecret"])!;
            var raw = Codec.FormEncode(clientId) + ":" + Codec.FormEncode(secret);
            headers["authorization"] = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(raw));
            return;
        }
        if (method == "client_secret_post")
        {
            body["client_id"] = clientId;
            body["client_secret"] = config.GetValueOrDefault("clientSecret") == null ? "" : Convert.ToString(config["clientSecret"])!;
            return;
        }
        if (key == null) throw new OidcError("config", "private_key_jwt has no signing key");
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var alg = config.GetValueOrDefault("privateKeyAlg") == null || Convert.ToString(config["privateKeyAlg"])!.Length == 0
            ? "RS256" : Convert.ToString(config["privateKeyAlg"])!;
        var header = new Dictionary<string, object?> { ["alg"] = alg, ["typ"] = "JWT" };
        var payload = new Dictionary<string, object?>
        {
            ["iss"] = clientId,
            ["sub"] = clientId,
            ["aud"] = audience,
            ["jti"] = Guid.NewGuid().ToString(),
            ["iat"] = now,
            ["exp"] = now + 60,
        };
        body["client_id"] = clientId;
        body["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
        body["client_assertion"] = JwsCrypto.SignCompact(header, payload, key, alg);
    }
}
