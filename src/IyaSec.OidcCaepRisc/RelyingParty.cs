// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using System.Text;

namespace IyaSec.Oidc;

/// <summary>A confidential OpenID Connect relying party. Tokens stay in this process.</summary>
public sealed class RelyingParty
{
    static readonly string[] Front = { "access_token", "id_token", "refresh_token", "token_type" };

    readonly Dictionary<string, object?> config;
    readonly Dictionary<string, object?> metadata;
    readonly JwsCrypto.Material? key;
    readonly List<string> algorithms;
    List<Dictionary<string, object?>>? jwks;
    readonly Dictionary<string, long> usedCodes = new();
    CachedCredentials? cached;

    RelyingParty(Dictionary<string, object?> config, Dictionary<string, object?> metadata, JwsCrypto.Material? key)
    {
        this.config = config;
        this.metadata = metadata;
        this.key = key;
        algorithms = Discovery.IdTokenAlgorithms(Jsons.List(metadata.GetValueOrDefault("id_token_signing_alg_values_supported")),
            config.GetValueOrDefault("idTokenSignedResponseAlg") == null ? null : Convert.ToString(config["idTokenSignedResponseAlg"]));
    }

    public IReadOnlyDictionary<string, object?> ConfigMap => config;
    public IReadOnlyDictionary<string, object?> Metadata => metadata;

    public static RelyingParty FromFile(string path) => Create(Config.ReadConfigFile(path));

    public static RelyingParty Create(Dictionary<string, object?>? config)
    {
        if (config == null) throw new OidcError("config", "the configuration must be a JSON object");
        var method = Convert.ToString(config.GetValueOrDefault("tokenEndpointAuthMethod"));
        if (method == "private_key_jwt" && !Text(config.GetValueOrDefault("privateKeyPem")))
        {
            throw new OidcError("config", "private_key_jwt needs a private key");
        }
        if (method != "private_key_jwt" && !Text(config.GetValueOrDefault("clientSecret")))
        {
            throw new OidcError("config", method + " needs a client secret");
        }
        var tls = TlsOf(config);
        if (config.GetValueOrDefault("allowInsecure") is not true)
        {
            var issuer = StringOrNull(config.GetValueOrDefault("issuer"));
            if (issuer != null && Discovery.Scheme(issuer) == "http")
            {
                throw new OidcError("config", "issuer must use https (set allowInsecure for a development provider)");
            }
        }
        Dictionary<string, object?>? metadata = Jsons.Map(config.GetValueOrDefault("metadata"));
        if (metadata == null)
        {
            if (!Text(config.GetValueOrDefault("metadataUrl"))) throw new OidcError("config", "metadataUrl or metadata is required");
            if (config.GetValueOrDefault("allowInsecure") is not true && Discovery.Scheme(Convert.ToString(config["metadataUrl"])) != "https")
            {
                throw new OidcError("config", "metadataUrl must use https (set allowInsecure for a development provider)");
            }
            metadata = Discovery.DiscoverProvider(Convert.ToString(config["metadataUrl"])!, tls);
        }
        if (config.GetValueOrDefault("allowInsecure") is not true)
        {
            foreach (var entry in metadata)
            {
                var http = entry.Value is string text && text.StartsWith("http:", StringComparison.Ordinal);
                if ((http && entry.Key.EndsWith("endpoint", StringComparison.Ordinal)) || (entry.Key == "jwks_uri" && http) || (entry.Key == "issuer" && http))
                {
                    throw new OidcError("discovery", entry.Key + " must use https: " + entry.Value);
                }
            }
        }
        var methods = Strings(metadata.GetValueOrDefault("token_endpoint_auth_methods_supported"));
        if (methods.Count > 0 && !methods.Contains(method)) throw new OidcError("discovery", "the provider does not advertise " + method);
        var challenges = Strings(metadata.GetValueOrDefault("code_challenge_methods_supported"));
        if (challenges.Count > 0 && !challenges.Contains("S256")) throw new OidcError("discovery", "the provider does not advertise PKCE S256");
        JwsCrypto.Material? key = Text(config.GetValueOrDefault("privateKeyPem"))
            ? JwsCrypto.LoadPrivateKey(Convert.ToString(config["privateKeyPem"])!, config.GetValueOrDefault("privateKeyAlg") == null ? "RS256" : Convert.ToString(config["privateKeyAlg"])!)
            : null;
        return new RelyingParty(config, metadata, key);
    }

    public Dictionary<string, string> Tls() => TlsOf(config);

    public Transaction Authorize(AuthorizeOptions? options = null)
    {
        var opts = options ?? new AuthorizeOptions();
        var redirectUri = opts.RedirectUri ?? Convert.ToString(config["redirectUri"])!;
        var scope = opts.Scope ?? Convert.ToString(config["scopes"])!;
        var state = Codec.RandomToken();
        var nonce = Codec.RandomToken();
        var verifier = Codec.RandomToken();
        var parameters = new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = Convert.ToString(config["clientId"])!,
            ["redirect_uri"] = redirectUri,
            ["scope"] = scope,
            ["state"] = state,
            ["nonce"] = nonce,
            ["code_challenge"] = Codec.CodeChallengeS256(verifier),
            ["code_challenge_method"] = "S256",
        };
        if (Text(opts.Prompt)) parameters["prompt"] = opts.Prompt!;
        if (Text(opts.LoginHint)) parameters["login_hint"] = opts.LoginHint!;
        if (opts.MaxAge != null) parameters["max_age"] = Convert.ToString(opts.MaxAge, System.Globalization.CultureInfo.InvariantCulture)!;
        if (Text(opts.AcrValues)) parameters["acr_values"] = opts.AcrValues!;
        var transaction = new Transaction
        {
            State = state,
            Nonce = nonce,
            CodeVerifier = verifier,
            RedirectUri = redirectUri,
            MaxAge = opts.MaxAge,
            ExpectedSub = Text(opts.ExpectedSub) ? opts.ExpectedSub : null,
        };
        var par = StringOrNull(metadata.GetValueOrDefault("pushed_authorization_request_endpoint"));
        var mode = Convert.ToString(config.GetValueOrDefault("par"));
        var usePar = mode == "always" || (mode == "auto" && par != null);
        if (mode == "always" && par == null) throw new OidcError("discovery", "par is always, and the provider has no pushed authorization endpoint");
        if (usePar && par != null)
        {
            var pushed = Form(par, parameters.ToDictionary(pair => pair.Key, pair => (object?)pair.Value));
            if (pushed.GetValueOrDefault("request_uri") is not string uri || uri.Length == 0)
            {
                throw new OidcError("protocol", "the pushed authorization response has no request_uri");
            }
            transaction.Url = WithQuery(Convert.ToString(metadata["authorization_endpoint"])!, new Dictionary<string, string>
            {
                ["client_id"] = Convert.ToString(config["clientId"])!,
                ["request_uri"] = uri,
            });
            return transaction;
        }
        transaction.Url = WithQuery(Convert.ToString(metadata["authorization_endpoint"])!, parameters);
        return transaction;
    }

    public Login Complete(IReadOnlyDictionary<string, string>? callback, Transaction? transaction)
    {
        if (callback != null)
        {
            foreach (var name in Front)
            {
                if (callback.TryGetValue(name, out var present) && present != null)
                {
                    throw new OidcError("validation", name + " was returned on the redirect, and a code-flow client refuses it");
                }
            }
        }
        if (callback != null && callback.ContainsKey("error"))
        {
            callback.TryGetValue("error_description", out var description);
            callback.TryGetValue("error", out var error);
            var message = string.IsNullOrEmpty(description) ? error ?? "" : error + ": " + description;
            throw new OidcError("protocol", message, null, error);
        }
        var state = callback != null && callback.TryGetValue("state", out var got) ? got : "";
        if (transaction == null || !Text(transaction.State) || !Same(state, transaction.State))
        {
            throw new OidcError("validation", "the callback state does not match this sign-in");
        }
        if (callback != null && callback.TryGetValue("iss", out var iss) && iss != null && Convert.ToString(metadata["issuer"]) != iss)
        {
            throw new OidcError("validation", "iss mismatch in the callback: " + iss);
        }
        if ((callback == null || !callback.ContainsKey("iss") || callback["iss"] == null) && metadata.GetValueOrDefault("authorization_response_iss_parameter_supported") is true)
        {
            throw new OidcError("validation", "iss is missing from the callback, and the provider requires it");
        }
        var code = callback != null && callback.TryGetValue("code", out var rawCode) ? rawCode : null;
        if (string.IsNullOrEmpty(code)) throw new OidcError("validation", "the callback has no code");
        RememberCode(code);
        var body = new Dictionary<string, object?>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = transaction.RedirectUri,
            ["code_verifier"] = transaction.CodeVerifier,
        };
        var tokens = Token(body);
        if (tokens.GetValueOrDefault("id_token") is not string) throw new OidcError("protocol", "the token response has no id_token");
        var extra = new Dictionary<string, object?>
        {
            ["nonce"] = transaction.Nonce,
            ["accessToken"] = tokens["access_token"],
            ["code"] = code,
        };
        if (transaction.MaxAge != null) extra["maxAge"] = transaction.MaxAge;
        var claims = ReadIdToken(Convert.ToString(tokens["id_token"])!, extra);
        if (Text(transaction.ExpectedSub) && transaction.ExpectedSub != Convert.ToString(claims.GetValueOrDefault("sub")))
        {
            throw new OidcError("validation", "the provider signed in a different account from the one requested");
        }
        return LoginFrom(tokens, claims);
    }

    public Login Refresh(string? refreshToken, Login? previous, string? scope = null)
    {
        if (!Text(refreshToken)) throw new OidcError("protocol", "there is no refresh token");
        var body = new Dictionary<string, object?>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken,
        };
        if (Text(scope)) body["scope"] = scope;
        var tokens = Token(new Dictionary<string, object?>(body));
        var claims = previous?.Claims;
        var idToken = tokens.GetValueOrDefault("id_token") as string ?? previous?.IdToken;
        if (tokens.GetValueOrDefault("id_token") is string)
        {
            if (previous == null) throw new OidcError("validation", "the refresh returned an ID token and there is no previous sign-in to check it against");
            claims = ReadIdToken(Convert.ToString(tokens["id_token"])!, new Dictionary<string, object?>
            {
                ["accessToken"] = tokens["access_token"],
                ["previousSub"] = previous.Subject,
            });
            idToken = Convert.ToString(tokens["id_token"]);
        }
        if (claims == null || !Text(idToken))
        {
            throw new OidcError("protocol", "the refresh returned no ID token and no previous sign-in was given");
        }
        var merged = new Dictionary<string, object?>(tokens)
        {
            ["refresh_token"] = tokens.GetValueOrDefault("refresh_token") is string rotated ? rotated : refreshToken,
            ["id_token"] = idToken,
        };
        return LoginFrom(merged, claims);
    }

    public Credentials ClientCredentials(string scope = "ssf.manage")
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        if (cached != null && cached.Scope == scope && cached.Until > now) return cached.Token;
        var minted = CredentialsFrom(Token(new Dictionary<string, object?>
        {
            ["grant_type"] = "client_credentials",
            ["scope"] = scope,
        }));
        var until = minted.ExpiresAt != null ? new DateTimeOffset(minted.ExpiresAt.Value).ToUnixTimeMilliseconds() - 30_000 : now + 60_000;
        cached = new CachedCredentials(scope, minted, until);
        return minted;
    }

    public Dictionary<string, object?> UserInfo(string accessToken, string? expectedSub)
    {
        if (!Text(expectedSub)) throw new OidcError("validation", "userinfo needs the subject to check the response against");
        if (!Text(metadata.GetValueOrDefault("userinfo_endpoint"))) throw new OidcError("discovery", "the provider has no userinfo_endpoint");
        var answer = Http.Send(Convert.ToString(metadata["userinfo_endpoint"])!, "GET", new Dictionary<string, string>
        {
            ["accept"] = "application/json, application/jwt",
            ["authorization"] = "Bearer " + accessToken,
        }, null, Tls(), "protocol");
        if (answer.Status == 401) throw new OidcError("protocol", "userinfo refused the access token", null, "invalid_token");
        if (answer.Status != 200) throw new OidcError("protocol", "userinfo answered " + answer.Status);
        Dictionary<string, object?> claims;
        if (answer.ContentType.Contains("application/jwt", StringComparison.Ordinal))
        {
            claims = ReadIdToken(answer.Body.Trim(), new Dictionary<string, object?> { ["algorithms"] = algorithms });
        }
        else
        {
            object? body;
            try
            {
                body = Jsons.Read(answer.Body);
            }
            catch (Exception err)
            {
                throw new OidcError("protocol", "userinfo did not answer JSON", err);
            }
            claims = Jsons.Map(body) ?? throw new OidcError("validation", "userinfo did not answer a JSON object");
        }
        if (expectedSub != Convert.ToString(claims.GetValueOrDefault("sub"))) throw new OidcError("validation", "userinfo sub does not match the ID token sub");
        return claims;
    }

    public string? EndSessionUrl(string? idToken, string? state, string? postLogoutRedirectUri = null, string? logoutHint = null)
    {
        if (!Text(metadata.GetValueOrDefault("end_session_endpoint"))) return null;
        var redirect = Text(postLogoutRedirectUri) ? postLogoutRedirectUri : StringOrNull(config.GetValueOrDefault("postLogoutRedirectUri"));
        var query = new Dictionary<string, string>();
        if (Text(idToken)) query["id_token_hint"] = idToken!;
        if (Text(redirect)) query["post_logout_redirect_uri"] = redirect!;
        query["client_id"] = Convert.ToString(config["clientId"])!;
        if (Text(logoutHint)) query["logout_hint"] = logoutHint!;
        if (Text(state)) query["state"] = state!;
        return WithQuery(Convert.ToString(metadata["end_session_endpoint"])!, query);
    }

    Dictionary<string, object?> ReadIdToken(string token, Dictionary<string, object?> extra)
    {
        var checks = new Dictionary<string, object?>
        {
            ["issuer"] = metadata["issuer"],
            ["clientId"] = config["clientId"],
            ["algorithms"] = extra.GetValueOrDefault("algorithms") ?? algorithms,
            ["jwks"] = Keys(false),
            ["clockToleranceSec"] = config.GetValueOrDefault("clockToleranceSec"),
            ["maxIdTokenAgeSec"] = config.GetValueOrDefault("maxIdTokenAgeSec"),
        };
        if (Text(config.GetValueOrDefault("clientSecret"))) checks["clientSecret"] = config["clientSecret"];
        foreach (var entry in extra)
        {
            if (entry.Key != "algorithms") checks[entry.Key] = entry.Value;
        }
        try
        {
            return IdToken.Validate(token, checks);
        }
        catch (OidcError err)
        {
            if (err.Code != "signature") throw;
            jwks = null;
            checks["jwks"] = Keys(true);
            return IdToken.Validate(token, checks);
        }
    }

    List<Dictionary<string, object?>> Keys(bool force)
    {
        if (!force && jwks != null) return jwks;
        jwks = IdToken.FetchJwks(Convert.ToString(metadata["jwks_uri"])!, Tls());
        return jwks;
    }

    Dictionary<string, object?> Token(Dictionary<string, object?> body)
    {
        var parsed = Form(Convert.ToString(metadata["token_endpoint"])!, body);
        if (parsed.GetValueOrDefault("access_token") is not string access || access.Length == 0)
        {
            throw new OidcError("protocol", "the token response has no access_token");
        }
        if (parsed.GetValueOrDefault("token_type") is not string tokenType || tokenType.Length == 0)
        {
            throw new OidcError("protocol", "the token response has no token_type");
        }
        if (tokenType.Equals("dpop", StringComparison.OrdinalIgnoreCase))
        {
            throw new OidcError("protocol", "the provider returned a DPoP token; this client asked for a Bearer token");
        }
        if (!tokenType.Equals("bearer", StringComparison.OrdinalIgnoreCase)) throw new OidcError("protocol", "the token response token_type is " + tokenType);
        var output = new Dictionary<string, object?>
        {
            ["access_token"] = access,
            ["token_type"] = tokenType,
        };
        if (parsed.GetValueOrDefault("id_token") is string id) output["id_token"] = id;
        if (parsed.GetValueOrDefault("refresh_token") is string refresh) output["refresh_token"] = refresh;
        if (parsed.GetValueOrDefault("expires_in") is byte or short or int or long or float or double or decimal) output["expires_in"] = parsed["expires_in"];
        if (parsed.GetValueOrDefault("scope") is string scope) output["scope"] = scope;
        return output;
    }

    Dictionary<string, object?> Form(string url, IDictionary<string, object?> body)
    {
        var headers = new Dictionary<string, string>
        {
            ["accept"] = "application/json",
            ["content-type"] = "application/x-www-form-urlencoded",
        };
        var fields = new Dictionary<string, object?>(body);
        ClientAuth.Apply(config, key, fields, headers, Convert.ToString(metadata["issuer"])!);
        var answer = Http.Send(url, "POST", headers, Encoding.UTF8.GetBytes(Codec.FormBody(fields)), Tls(), "protocol");
        object? parsed;
        try
        {
            parsed = string.IsNullOrEmpty(answer.Body) ? new Dictionary<string, object?>() : Jsons.Read(answer.Body);
        }
        catch (Exception err)
        {
            throw new OidcError("protocol", url + " answered " + answer.Status + " with no JSON", err);
        }
        var doc = Jsons.Map(parsed) ?? new Dictionary<string, object?>();
        if (answer.Status != 200 && answer.Status != 201)
        {
            var oauth = doc.GetValueOrDefault("error") as string;
            var description = doc.GetValueOrDefault("error_description") as string ?? "";
            var message = url + " answered " + answer.Status;
            if (oauth != null) message += ": " + oauth;
            if (description.Length > 0) message += ": " + description;
            throw new OidcError("protocol", message, null, oauth);
        }
        return doc;
    }

    void RememberCode(string code)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var cutoff = now - 10 * 60;
        lock (usedCodes)
        {
            foreach (var key in usedCodes.Where(entry => entry.Value < cutoff).Select(entry => entry.Key).ToList()) usedCodes.Remove(key);
            var digest = Codec.Hex(Codec.Sha256(Encoding.UTF8.GetBytes(code)));
            if (usedCodes.ContainsKey(digest)) throw new OidcError("validation", "this authorization code was already used");
            usedCodes[digest] = now;
        }
    }

    static Login LoginFrom(Dictionary<string, object?> tokens, Dictionary<string, object?> claims)
    {
        var login = new Login
        {
            Subject = Convert.ToString(claims.GetValueOrDefault("sub")) ?? "",
            Issuer = Convert.ToString(claims.GetValueOrDefault("iss")) ?? "",
            Claims = claims,
            AccessToken = Convert.ToString(tokens.GetValueOrDefault("access_token")) ?? "",
            IdToken = tokens.GetValueOrDefault("id_token") as string ?? "",
            TokenType = Convert.ToString(tokens.GetValueOrDefault("token_type")) ?? "",
            Email = Claim(claims, "email"),
            Name = Claim(claims, "name"),
            PreferredUsername = Claim(claims, "preferred_username"),
            Sid = Claim(claims, "sid"),
        };
        if (tokens.GetValueOrDefault("refresh_token") is string refresh) login.RefreshToken = refresh;
        if (tokens.GetValueOrDefault("expires_in") is byte or short or int or long or float or double or decimal)
        {
            login.ExpiresAt = DateTime.UtcNow.AddSeconds(Config.AsDouble(tokens["expires_in"]));
        }
        if (tokens.GetValueOrDefault("scope") is string scope) login.Scope = scope;
        return login;
    }

    static Credentials CredentialsFrom(Dictionary<string, object?> tokens)
    {
        var output = new Credentials
        {
            AccessToken = Convert.ToString(tokens.GetValueOrDefault("access_token")) ?? "",
            TokenType = Convert.ToString(tokens.GetValueOrDefault("token_type")) ?? "",
        };
        if (tokens.GetValueOrDefault("expires_in") is byte or short or int or long or float or double or decimal)
        {
            output.ExpiresAt = DateTime.UtcNow.AddSeconds(Config.AsDouble(tokens["expires_in"]));
        }
        if (tokens.GetValueOrDefault("scope") is string scope) output.Scope = scope;
        return output;
    }

    static string WithQuery(string baseUrl, IDictionary<string, string> parameters)
    {
        var uri = new Uri(baseUrl);
        var path = string.IsNullOrEmpty(uri.AbsolutePath) ? "/" : uri.AbsolutePath;
        var pairs = parameters.Select(pair => new KeyValuePair<string, object?>(pair.Key, pair.Value));
        return uri.GetComponents(UriComponents.SchemeAndServer, UriFormat.SafeUnescaped) + path + "?" + Codec.FormBody(pairs);
    }

    static Dictionary<string, string> TlsOf(IReadOnlyDictionary<string, object?> config)
    {
        if (!Text(config.GetValueOrDefault("tlsCa"))) return new Dictionary<string, string>();
        return new Dictionary<string, string> { ["ca"] = Convert.ToString(config["tlsCa"])! };
    }

    static string? Claim(Dictionary<string, object?> claims, string name)
    {
        return claims.GetValueOrDefault(name) is string text && text.Length > 0 ? text : null;
    }

    static bool Same(string? left, string? right)
    {
        if (left == null || right == null) return false;
        var a = Encoding.UTF8.GetBytes(left);
        var b = Encoding.UTF8.GetBytes(right);
        return a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    }

    static bool Text(object? value) => value is string text && text.Length > 0;

    static string? StringOrNull(object? value) => value is string text && text.Length > 0 ? text : null;

    static List<string> Strings(object? value)
    {
        var output = new List<string>();
        if (Jsons.List(value) is { } items) foreach (var item in items) output.Add(Convert.ToString(item) ?? "");
        return output;
    }

    sealed record CachedCredentials(string Scope, Credentials Token, long Until);

    public sealed class Transaction
    {
        public string? Url { get; set; }
        public string? State { get; set; }
        public string? Nonce { get; set; }
        public string? CodeVerifier { get; set; }
        public string? RedirectUri { get; set; }
        public int? MaxAge { get; set; }
        public string? ExpectedSub { get; set; }
    }

    public sealed class AuthorizeOptions
    {
        public string? RedirectUri { get; set; }
        public string? Scope { get; set; }
        public string? Prompt { get; set; }
        public string? LoginHint { get; set; }
        public int? MaxAge { get; set; }
        public string? AcrValues { get; set; }
        public string? ExpectedSub { get; set; }
    }

    public sealed class Login
    {
        public string Subject { get; set; } = "";
        public string Issuer { get; set; } = "";
        public Dictionary<string, object?> Claims { get; set; } = new();
        public string AccessToken { get; set; } = "";
        public string IdToken { get; set; } = "";
        public string TokenType { get; set; } = "";
        public string? Email { get; set; }
        public string? Name { get; set; }
        public string? PreferredUsername { get; set; }
        public string? Sid { get; set; }
        public string? RefreshToken { get; set; }
        public DateTime? ExpiresAt { get; set; }
        public string? Scope { get; set; }
    }

    public sealed class Credentials
    {
        public string AccessToken { get; set; } = "";
        public string TokenType { get; set; } = "";
        public DateTime? ExpiresAt { get; set; }
        public string? Scope { get; set; }
    }
}
