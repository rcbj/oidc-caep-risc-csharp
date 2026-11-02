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
        output["redirectUri"] = CheckRedirect(redirectUri, "redirectUri", allowInsecure);
        if (postLogout.Length > 0) output["postLogoutRedirectUri"] = CheckRedirect(postLogout, "postLogoutRedirectUri", allowInsecure);
        output["scopes"] = scopes;
        if (Truthy(doc.GetValueOrDefault("idTokenSignedResponseAlg"))) output["idTokenSignedResponseAlg"] = doc["idTokenSignedResponseAlg"];
        output["par"] = par;
        output["clockToleranceSec"] = doc.GetValueOrDefault("clockToleranceSec") ?? 30L;
        output["maxIdTokenAgeSec"] = doc.GetValueOrDefault("maxIdTokenAgeSec") ?? 600L;
        output["allowInsecure"] = allowInsecure;
        if (!string.IsNullOrEmpty(tlsCa)) output["tlsCa"] = tlsCa;
        if (!signals) output["signals"] = false;
        if (ssf != null) output["ssf"] = ssf;
        return output;
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

    static string CheckRedirect(string value, string name, bool allowInsecure)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || (uri.Scheme != "http" && uri.Scheme != "https") || string.IsNullOrEmpty(uri.Host))
        {
            throw new OidcError("config", name + " is not a URL: " + value);
        }
        if (uri.Scheme == "https") return value;
        if (uri.Scheme == "http" && (Loopback(uri.Host) || allowInsecure)) return value;
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
