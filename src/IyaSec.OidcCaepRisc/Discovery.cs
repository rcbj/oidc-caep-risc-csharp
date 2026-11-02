// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

namespace IyaSec.Oidc;

/// <summary>OpenID Provider discovery for a confidential Authorization Code client.</summary>
public static class Discovery
{
    public static readonly IReadOnlyList<string> AsymmetricJwsAlgs = JwsCrypto.Supported;
    public const string DefaultScopes = "openid profile email offline_access ssf.read ssf.manage";

    static readonly string[] Required =
    {
        "issuer", "authorization_endpoint", "token_endpoint", "jwks_uri",
        "response_types_supported", "subject_types_supported", "id_token_signing_alg_values_supported",
    };

    public static string IssuerFromMetadataUrl(string metadataUrl)
    {
        if (!Uri.TryCreate(metadataUrl, UriKind.Absolute, out var uri) || (uri.Scheme != "http" && uri.Scheme != "https") || string.IsNullOrEmpty(uri.Host))
        {
            throw new OidcError("config", "metadataUrl is not a URL: " + metadataUrl);
        }
        var path = uri.AbsolutePath;
        const string marker = "/.well-known/openid-configuration";
        var at = path.IndexOf(marker, StringComparison.Ordinal);
        if (at < 0) throw new OidcError("config", "metadataUrl must be the openid-configuration URL, not " + metadataUrl);
        var prefix = path[..at].TrimEnd('/');
        return uri.GetComponents(UriComponents.SchemeAndServer, UriFormat.SafeUnescaped) + prefix;
    }

    public static Dictionary<string, object?> ValidateProviderMetadata(object? raw, string? expectedIssuer)
    {
        var doc = Jsons.Map(raw) ?? throw new OidcError("discovery", "OpenID Provider metadata must be a JSON object");
        var missing = Required.Where(key => !doc.ContainsKey(key)).ToList();
        if (missing.Count > 0) throw new OidcError("discovery", "OpenID Provider metadata is missing " + string.Join(", ", missing));
        var metadata = new Dictionary<string, object?>
        {
            ["issuer"] = MustBeUrl(doc["issuer"], "issuer"),
            ["authorization_endpoint"] = MustBeUrl(doc["authorization_endpoint"], "authorization_endpoint"),
            ["token_endpoint"] = MustBeUrl(doc["token_endpoint"], "token_endpoint"),
            ["jwks_uri"] = MustBeUrl(doc["jwks_uri"], "jwks_uri"),
            ["response_types_supported"] = doc["response_types_supported"],
            ["subject_types_supported"] = doc["subject_types_supported"],
            ["id_token_signing_alg_values_supported"] = doc["id_token_signing_alg_values_supported"],
        };
        foreach (var key in new[] { "userinfo_endpoint", "end_session_endpoint", "pushed_authorization_request_endpoint", "revocation_endpoint" })
        {
            if (doc.TryGetValue(key, out var value) && value != null) metadata[key] = MustBeUrl(value, key);
        }
        foreach (var key in new[] { "token_endpoint_auth_methods_supported", "code_challenge_methods_supported", "scopes_supported", "grant_types_supported" })
        {
            if (doc.TryGetValue(key, out var value) && value != null)
            {
                var items = Jsons.List(value) ?? throw new OidcError("discovery", key + " must be an array");
                metadata[key] = Strings(items);
            }
        }
        if (doc.TryGetValue("authorization_response_iss_parameter_supported", out var issParam) && issParam != null)
        {
            metadata["authorization_response_iss_parameter_supported"] = issParam is true;
        }
        var responseTypes = Jsons.List(metadata["response_types_supported"]);
        var responseNames = responseTypes == null ? new List<string>() : Strings(responseTypes);
        if (responseTypes == null || !responseNames.Contains("code"))
        {
            throw new OidcError("discovery", "OpenID Provider does not support response_type=code");
        }
        metadata["response_types_supported"] = responseNames;
        var subjects = Jsons.List(metadata["subject_types_supported"]) ?? throw new OidcError("discovery", "subject_types_supported must be an array");
        metadata["subject_types_supported"] = Strings(subjects);
        var algs = Jsons.List(metadata["id_token_signing_alg_values_supported"]) ?? throw new OidcError("discovery", "id_token_signing_alg_values_supported must be an array");
        metadata["id_token_signing_alg_values_supported"] = Strings(algs);
        if (expectedIssuer != null && !expectedIssuer.Equals(metadata["issuer"]))
        {
            throw new OidcError("discovery", "issuer mismatch: expected \"" + expectedIssuer + "\", got \"" + metadata["issuer"] + "\"");
        }
        return metadata;
    }

    public static Dictionary<string, object?> DiscoverProvider(string metadataUrl, IReadOnlyDictionary<string, string>? tls)
    {
        var expected = IssuerFromMetadataUrl(metadataUrl);
        var answer = Http.Send(metadataUrl, "GET", new Dictionary<string, string> { ["accept"] = "application/json" }, null, tls, "discovery");
        if (answer.Status != 200) throw new OidcError("discovery", metadataUrl + " answered " + answer.Status);
        object? body;
        try
        {
            body = Jsons.Read(answer.Body);
        }
        catch (Exception err)
        {
            throw new OidcError("discovery", metadataUrl + " did not answer JSON", err);
        }
        return ValidateProviderMetadata(body, expected);
    }

    public static List<string> WellKnownUrls(string issuer, string suffix)
    {
        var uri = new Uri(issuer);
        var path = uri.AbsolutePath.TrimEnd('/');
        var origin = uri.GetComponents(UriComponents.SchemeAndServer, UriFormat.SafeUnescaped);
        var inserted = origin + "/.well-known/" + suffix + path;
        var appended = origin + path + "/.well-known/" + suffix;
        if (inserted == appended) return new List<string> { inserted };
        return new List<string> { inserted, appended };
    }

    public static List<string> IdTokenAlgorithms(IEnumerable<object?>? advertised, string? pinned)
    {
        var names = advertised?.Select(item => Convert.ToString(item) ?? "").ToList() ?? new List<string>();
        if (!string.IsNullOrEmpty(pinned))
        {
            if (!names.Contains(pinned)) throw new OidcError("discovery", "the provider does not advertise id_token alg " + pinned);
            return new List<string> { pinned };
        }
        var allowed = names.Where(alg => AsymmetricJwsAlgs.Contains(alg)).ToList();
        if (allowed.Count == 0)
        {
            throw new OidcError("discovery", "none of the provider's ID token algorithms can be verified (" + string.Join(", ", names) + ")");
        }
        return allowed;
    }

    public static string Scheme(string? value)
    {
        var text = value != null && value.StartsWith("http", StringComparison.Ordinal) ? value : "https://" + value;
        return Uri.TryCreate(text, UriKind.Absolute, out var uri) ? uri.Scheme : "";
    }

    static string MustBeUrl(object? value, string name)
    {
        if (value is not string text || text.Length == 0) throw new OidcError("discovery", "OpenID Provider metadata " + name + " is missing");
        if (!Uri.TryCreate(text, UriKind.Absolute, out var uri) || (uri.Scheme != "http" && uri.Scheme != "https") || string.IsNullOrEmpty(uri.Host))
        {
            throw new OidcError("discovery", "OpenID Provider metadata " + name + " is not a valid URL");
        }
        if (name == "issuer" && (!string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment)))
        {
            throw new OidcError("discovery", "issuer must not contain a query or fragment");
        }
        return text;
    }

    static List<string> Strings(IEnumerable<object?> items) => items.Select(item => Convert.ToString(item) ?? "").ToList();
}
