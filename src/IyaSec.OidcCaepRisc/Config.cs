// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

namespace IyaSec.Oidc;

/// <summary>Configuration. JSON keys are the same names the Python library reads.</summary>
public static class Config
{
    public static readonly IReadOnlyList<string> AuthMethods = new[] { "client_secret_basic", "client_secret_post", "private_key_jwt" };
    public static Func<string, string?> Environment = static name => System.Environment.GetEnvironmentVariable(name);

    public static Dictionary<string, object?> ReadConfigFile(string path)
    {
        var file = Path.GetFullPath(path);
        object? raw;
        try
        {
            raw = Jsons.Read(File.ReadAllText(file));
        }
        catch (Exception err)
        {
            throw new OidcError("config", "could not read " + path + ": " + err.Message, err);
        }
        return ResolveConfig(raw, Path.GetDirectoryName(file) ?? ".");
    }

    public static Dictionary<string, object?> ResolveConfig(object? raw, string baseDir)
    {
        var doc = Jsons.Map(raw) ?? throw new OidcError("config", "the configuration must be a JSON object");
        var clientId = Text(doc.ContainsKey("clientId") && doc["clientId"] != null ? doc["clientId"] : doc.GetValueOrDefault("client_id")).Trim();
        if (clientId.Length == 0) throw new OidcError("config", "client_id is required");
        var methodRaw = doc.GetValueOrDefault("tokenEndpointAuthMethod");
        var method = methodRaw == null || Convert.ToString(methodRaw)!.Length == 0 ? "client_secret_basic" : Convert.ToString(methodRaw)!;
        if (method == "none")
        {
            throw new OidcError("config", "tokenEndpointAuthMethod \"none\" is a public client; this library authenticates a confidential client");
        }
        if (!AuthMethods.Contains(method))
        {
            throw new OidcError("config", "tokenEndpointAuthMethod must be " + string.Join(", ", AuthMethods) + ", not " + method);
        }
        var redirectUri = Text(doc.ContainsKey("redirectUri") && doc["redirectUri"] != null ? doc["redirectUri"] : doc.GetValueOrDefault("redirect_uri")).Trim();
        if (redirectUri.Length == 0) throw new OidcError("config", "redirectUri is required");
        var allowInsecure = doc.GetValueOrDefault("allowInsecure") is true;
        var signalsPresent = doc.ContainsKey("signals");
        var signals = SignalsOn(signalsPresent ? doc["signals"] : null);
        string scopes;
        if (!doc.ContainsKey("scopes") || doc["scopes"] == null) scopes = Discovery.DefaultScopes.Trim();
        else if (Jsons.List(doc["scopes"]) is { } items) scopes = JoinScopes(items);
        else scopes = Text(doc["scopes"]).Trim();
        if (!signals)
        {
            scopes = string.Join(" ", scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries).Where(part => part != "ssf.read" && part != "ssf.manage"));
        }
        if (!scopes.Split(' ').Contains("openid")) throw new OidcError("config", "scopes must include openid");
        var par = Convert.ToString(doc.ContainsKey("par") && doc["par"] != null ? doc["par"] : "auto")!;
        if (par != "auto" && par != "always" && par != "never") throw new OidcError("config", "par must be auto, always, or never");
        string? issuer = doc.GetValueOrDefault("issuer") == null ? null : Text(doc["issuer"]).Trim();
        if (issuer != null && issuer.Length == 0) issuer = null;
        string? metadataUrl = doc.GetValueOrDefault("metadataUrl") == null ? null : Text(doc["metadataUrl"]).Trim();
        if (metadataUrl != null && metadataUrl.Length == 0) metadataUrl = null;
        if (metadataUrl != null)
        {
            var fromUrl = Discovery.IssuerFromMetadataUrl(metadataUrl);
            if (issuer != null && issuer != fromUrl)
            {
                throw new OidcError("config", "issuer " + issuer + " is not the issuer of " + metadataUrl + " (" + fromUrl + ")");
            }
            issuer = fromUrl;
        }
        Dictionary<string, object?>? metadata = null;
        if (doc.GetValueOrDefault("metadataFile") != null)
        {
            var named = Convert.ToString(doc["metadataFile"])!;
            var full = Path.IsPathRooted(named) ? named : Path.GetFullPath(Path.Combine(baseDir, named));
            object? body;
            try
            {
                body = Jsons.Read(File.ReadAllText(full));
            }
            catch (Exception err)
            {
                throw new OidcError("config", "could not read metadata at " + full + ": " + err.Message, err);
            }
            metadata = Discovery.ValidateProviderMetadata(body, issuer);
            issuer = Convert.ToString(metadata["issuer"]);
        }
        if (metadataUrl == null && metadata == null) throw new OidcError("config", "metadataUrl or metadataFile is required");
        var needsSecret = method != "private_key_jwt";
        string? clientSecret = null;
        if (Truthy(doc.GetValueOrDefault("clientSecret"))) clientSecret = SecretValue(Convert.ToString(doc["clientSecret"])!, baseDir, "the client secret");
        if (needsSecret && string.IsNullOrEmpty(clientSecret)) throw new OidcError("config", method + " needs clientSecret");
        string? privateKeyPem = null;
        if (Truthy(doc.GetValueOrDefault("privateKey"))) privateKeyPem = KeyValue(Convert.ToString(doc["privateKey"])!, baseDir, "the private key");
        if (method == "private_key_jwt" && string.IsNullOrEmpty(privateKeyPem)) throw new OidcError("config", "private_key_jwt needs privateKey");
        var tlsCa = ReadTrust(doc.GetValueOrDefault("tlsCa"), baseDir);
        var postRaw = doc.ContainsKey("postLogoutRedirectUri") ? doc["postLogoutRedirectUri"] : doc.GetValueOrDefault("post_logout_redirect_uri");
        var postLogout = Text(postRaw).Trim();
        Dictionary<string, object?>? ssf = null;
        var ssfDoc = Jsons.Map(doc.GetValueOrDefault("ssf"));
        if (signals && ssfDoc != null && Truthy(ssfDoc.GetValueOrDefault("transmitter")))
        {
            var transmitter = Convert.ToString(ssfDoc["transmitter"])!.TrimEnd('/');
            if (!transmitter.StartsWith("http://", StringComparison.Ordinal) && !transmitter.StartsWith("https://", StringComparison.Ordinal))
            {
                throw new OidcError("config", "ssf.transmitter must be an http(s) URL");
            }
            ssf = new Dictionary<string, object?> { ["transmitter"] = transmitter };
            if (Truthy(ssfDoc.GetValueOrDefault("pollIntervalMs"))) ssf["pollIntervalMs"] = ssfDoc["pollIntervalMs"];
        }
        var output = new Dictionary<string, object?>();
        if (issuer != null) output["issuer"] = issuer;
        if (metadataUrl != null) output["metadataUrl"] = metadataUrl;
        if (metadata != null) output["metadata"] = metadata;
        output["clientId"] = clientId;
        if (!string.IsNullOrEmpty(clientSecret)) output["clientSecret"] = clientSecret;
        if (!string.IsNullOrEmpty(privateKeyPem)) output["privateKeyPem"] = privateKeyPem;
        output["privateKeyAlg"] = Truthy(doc.GetValueOrDefault("privateKeyAlg")) ? doc["privateKeyAlg"] : "RS256";
        output["tokenEndpointAuthMethod"] = method;
        output["redirectUri"] = CheckRedirect(redirectUri, "redirectUri");
        if (postLogout.Length > 0) output["postLogoutRedirectUri"] = CheckRedirect(postLogout, "postLogoutRedirectUri");
        output["scopes"] = scopes;
        if (Truthy(doc.GetValueOrDefault("idTokenSignedResponseAlg"))) output["idTokenSignedResponseAlg"] = doc["idTokenSignedResponseAlg"];
        output["par"] = par;
        output["clockToleranceSec"] = doc.GetValueOrDefault("clockToleranceSec") ?? 30L;
        output["maxIdTokenAgeSec"] = doc.GetValueOrDefault("maxIdTokenAgeSec") ?? 600L;
        output["allowInsecure"] = allowInsecure;
        if (!string.IsNullOrEmpty(tlsCa)) output["tlsCa"] = tlsCa;
        if (!signals) output["signals"] = false;
        if (ssf != null) output["ssf"] = ssf;
        foreach (var name in new[] { "dpop", "idTokenSigningAlgs", "requireIdTokenTypAndAtHash", "acrValues" })
        {
            if (doc.TryGetValue(name, out var value) && value != null) output[name] = value;
        }
        if (Truthy(doc.GetValueOrDefault("dpopKey"))) output["dpopKey"] = KeyValue(Convert.ToString(doc["dpopKey"])!, baseDir, "the DPoP key");
        return ApplyDefaults(output);
    }

    /// <summary>The ID token signing algorithms accepted when <c>idTokenSigningAlgs</c> is not set.</summary>
    public static readonly IReadOnlyList<string> DefaultIdTokenSigningAlgs = new[] { "RS256" };

    /// <summary>
    /// The defaults and checks every way of creating a relying party shares, whether the
    /// configuration came from a file (<see cref="ResolveConfig"/>) or was built in code and given to
    /// <see cref="RelyingParty.Create"/>: <c>par</c> and <c>dpop</c> (<c>auto</c>),
    /// <c>clockToleranceSec</c> (30), <c>maxIdTokenAgeSec</c> (600), <c>idTokenSigningAlgs</c>
    /// (<c>["RS256"]</c>), <c>requireIdTokenTypAndAtHash</c> (true), and the redirect-URI rule
    /// (https, or http on a loopback host). Returns a new dictionary; the argument is not changed.
    /// </summary>
    public static Dictionary<string, object?> ApplyDefaults(IReadOnlyDictionary<string, object?> config)
    {
        var output = new Dictionary<string, object?>();
        foreach (var entry in config) output[entry.Key] = entry.Value;
        var clientId = Text(output.GetValueOrDefault("clientId")).Trim();
        if (clientId.Length == 0) throw new OidcError("config", "client_id is required");
        output["clientId"] = clientId;
        var methodRaw = output.GetValueOrDefault("tokenEndpointAuthMethod");
        var method = methodRaw == null || Text(methodRaw).Length == 0 ? "client_secret_basic" : Text(methodRaw);
        if (method == "none")
        {
            throw new OidcError("config", "tokenEndpointAuthMethod \"none\" is a public client; this library authenticates a confidential client");
        }
        if (!AuthMethods.Contains(method))
        {
            throw new OidcError("config", "tokenEndpointAuthMethod must be " + string.Join(", ", AuthMethods) + ", not " + method);
        }
        output["tokenEndpointAuthMethod"] = method;
        var allowInsecure = output.GetValueOrDefault("allowInsecure") is true;
        output["allowInsecure"] = allowInsecure;
        var redirectUri = Text(output.GetValueOrDefault("redirectUri")).Trim();
        if (redirectUri.Length == 0) throw new OidcError("config", "redirectUri is required");
        output["redirectUri"] = CheckRedirect(redirectUri, "redirectUri");
        var postLogout = Text(output.GetValueOrDefault("postLogoutRedirectUri")).Trim();
        if (postLogout.Length > 0) output["postLogoutRedirectUri"] = CheckRedirect(postLogout, "postLogoutRedirectUri");
        else output.Remove("postLogoutRedirectUri");
        string scopes;
        if (output.GetValueOrDefault("scopes") == null) scopes = Discovery.DefaultScopes.Trim();
        else if (Jsons.List(output["scopes"]) is { } items) scopes = JoinScopes(items);
        else scopes = Text(output["scopes"]).Trim();
        if (!scopes.Split(' ').Contains("openid")) throw new OidcError("config", "scopes must include openid");
        output["scopes"] = scopes;
        output["par"] = Mode(output.GetValueOrDefault("par"), "par");
        output["dpop"] = Mode(output.GetValueOrDefault("dpop"), "dpop");
        if (!Truthy(output.GetValueOrDefault("dpopKey"))) output.Remove("dpopKey");
        else if (output["dpopKey"] is not string) throw new OidcError("config", "dpopKey must be a PEM private key");
        output["clockToleranceSec"] = Seconds(output.GetValueOrDefault("clockToleranceSec"), 30, "clockToleranceSec");
        output["maxIdTokenAgeSec"] = Seconds(output.GetValueOrDefault("maxIdTokenAgeSec"), 600, "maxIdTokenAgeSec");
        if (Truthy(output.GetValueOrDefault("idTokenSignedResponseAlg")))
        {
            var pinned = Text(output["idTokenSignedResponseAlg"]).Trim();
            if (pinned.Equals("none", StringComparison.OrdinalIgnoreCase)) throw new OidcError("config", "idTokenSignedResponseAlg must not be none");
            output["idTokenSignedResponseAlg"] = pinned;
        }
        else
        {
            output.Remove("idTokenSignedResponseAlg");
        }
        output["idTokenSigningAlgs"] = Algorithms(output.GetValueOrDefault("idTokenSigningAlgs"));
        var require = output.GetValueOrDefault("requireIdTokenTypAndAtHash");
        if (require == null) output["requireIdTokenTypAndAtHash"] = true;
        else if (require is not bool) throw new OidcError("config", "requireIdTokenTypAndAtHash must be true or false");
        var acr = output.GetValueOrDefault("acrValues");
        var acrText = acr == null ? "" : Jsons.List(acr) is { } acrItems ? JoinScopes(acrItems) : Text(acr).Trim();
        if (acrText.Length > 0) output["acrValues"] = acrText;
        else output.Remove("acrValues");
        if (!Truthy(output.GetValueOrDefault("privateKeyAlg"))) output["privateKeyAlg"] = "RS256";
        return output;
    }

    /// <summary>
    /// Checks a redirect URI (the configured one, a post-logout one, or a per-request override):
    /// https, or http on a loopback host (<c>localhost</c>, <c>127.0.0.1</c>, <c>[::1]</c>).
    /// <c>allowInsecure</c> does not relax this rule; it only lets the provider's own endpoints use http.
    /// </summary>
    public static string CheckRedirectUri(string value, string name) => CheckRedirect(value, name);

    static string Mode(object? value, string name)
    {
        var text = value == null ? "auto" : Text(value);
        if (text != "auto" && text != "always" && text != "never") throw new OidcError("config", name + " must be auto, always, or never");
        return text;
    }

    static object Seconds(object? value, long fallback, string name)
    {
        if (value == null) return fallback;
        if (value is not (byte or short or int or long or float or double or decimal) || AsDouble(value) < 0)
        {
            throw new OidcError("config", name + " must be a number of seconds");
        }
        return value;
    }

    static List<object?> Algorithms(object? value)
    {
        List<string> names;
        if (value == null) names = new List<string>(DefaultIdTokenSigningAlgs);
        else if (Jsons.List(value) is { } items) names = items.Select(item => Text(item).Trim()).Where(item => item.Length > 0).ToList();
        else if (value is string text) names = text.Split(new[] { ' ', ',' }, StringSplitOptions.RemoveEmptyEntries).ToList();
        else throw new OidcError("config", "idTokenSigningAlgs must be a list of algorithm names");
        if (names.Count == 0) throw new OidcError("config", "idTokenSigningAlgs must name at least one algorithm");
        foreach (var name in names)
        {
            if (name.Equals("none", StringComparison.OrdinalIgnoreCase)) throw new OidcError("config", "idTokenSigningAlgs must not include none");
        }
        return names.Distinct().Cast<object?>().ToList();
    }

    static bool SignalsOn(object? value)
    {
        if (value == null || value is true) return true;
        if (value is false) return false;
        throw new OidcError("config", "signals must be true or false");
    }

    static string JoinScopes(IEnumerable<object?> items)
    {
        return string.Join(" ", items.Select(item => Convert.ToString(item)?.Trim() ?? "").Where(part => part.Length > 0));
    }

    static string SecretValue(string raw, string baseDir, string what)
    {
        if (raw.StartsWith("env:", StringComparison.Ordinal))
        {
            var name = raw[4..];
            var value = Environment(name);
            if (string.IsNullOrEmpty(value)) throw new OidcError("config", what + " reads " + name + ", and that variable is empty");
            return value;
        }
        if (raw.StartsWith("file:", StringComparison.Ordinal)) return ReadPath(raw[5..], baseDir, what);
        return raw;
    }

    static string KeyValue(string raw, string baseDir, string what)
    {
        if (raw.StartsWith("env:", StringComparison.Ordinal) || raw.StartsWith("file:", StringComparison.Ordinal) || raw.Contains("-----BEGIN", StringComparison.Ordinal))
        {
            return SecretValue(raw, baseDir, what);
        }
        return ReadPath(raw, baseDir, what);
    }

    static string ReadPath(string path, string baseDir, string what)
    {
        var full = Path.IsPathRooted(path) ? path : Path.GetFullPath(Path.Combine(baseDir, path));
        try
        {
            return File.ReadAllText(full).Trim();
        }
        catch (Exception err)
        {
            throw new OidcError("config", "could not read " + what + " at " + full + ": " + err.Message, err);
        }
    }

    static string? ReadTrust(object? raw, string baseDir)
    {
        if (raw == null) return null;
        var value = Convert.ToString(raw)?.Trim() ?? "";
        if (value.Length == 0) return null;
        if (value.Contains("-----BEGIN", StringComparison.Ordinal)) return value;
        if (value.StartsWith("env:", StringComparison.Ordinal))
        {
            var found = Environment(value[4..]);
            return string.IsNullOrEmpty(found) ? null : found;
        }
        var path = value.StartsWith("file:", StringComparison.Ordinal) ? value[5..] : value;
        var full = Path.IsPathRooted(path) ? path : Path.GetFullPath(Path.Combine(baseDir, path));
        try
        {
            return File.ReadAllText(full);
        }
        catch (IOException)
        {
            return null;
        }
    }

    static string CheckRedirect(string value, string name)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || (uri.Scheme != "http" && uri.Scheme != "https") || string.IsNullOrEmpty(uri.Host))
        {
            throw new OidcError("config", name + " is not a URL: " + value);
        }
        if (uri.Scheme == "https") return value;
        if (uri.Scheme == "http" && Loopback(uri.Host)) return value;
        throw new OidcError("config", name + " must use https, or http on loopback: " + value);
    }

    static bool Loopback(string host) => host is "localhost" or "127.0.0.1" or "::1" or "[::1]";

    public static bool Truthy(object? value)
    {
        if (value == null || value is false) return false;
        if (value is string text) return text.Length > 0;
        if (value is byte or short or int or long or float or double or decimal) return AsDouble(value) != 0;
        return true;
    }

    public static double AsDouble(object? value)
    {
        return value switch
        {
            byte number => number,
            short number => number,
            int number => number,
            long number => number,
            float number => number,
            double number => number,
            decimal number => (double)number,
            _ => 0,
        };
    }

    static string Text(object? value) => value == null ? "" : Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? "";
}
