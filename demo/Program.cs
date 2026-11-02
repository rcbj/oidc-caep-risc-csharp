// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using IyaSec.Oidc;
using static DemoSupport;

var options = ParseArgs(args);
var configPath = options.Config;
if (string.IsNullOrEmpty(configPath)) configPath = Environment.GetEnvironmentVariable("OIDC_CONFIG");
if (!string.IsNullOrEmpty(options.Config)) Environment.SetEnvironmentVariable("OIDC_CONFIG", options.Config);
if (string.IsNullOrEmpty(configPath))
{
    configPath = File.Exists("demo/oidc.json") ? "demo/oidc.json" : "oidc.json";
}
var publicGiven = !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("PUBLIC_URL"))
    || !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("OIDC_PUBLIC_URL_GIVEN"));
var publicUrl = Environment.GetEnvironmentVariable("PUBLIC_URL") ?? "";
if (!string.IsNullOrEmpty(options.PublicUrl))
{
    publicUrl = options.PublicUrl.TrimEnd('/');
    publicGiven = true;
}
var secretText = Environment.GetEnvironmentVariable("SESSION_SECRET");
var secret = string.IsNullOrEmpty(secretText) ? RandomNumberGenerator.GetBytes(32) : Encoding.UTF8.GetBytes(secretText);
var port = EnvPort();
var application = new DemoApp(secret, configPath, publicUrl, publicGiven);
if (File.Exists(configPath))
{
    try
    {
        var doc = Jsons.Map(Jsons.Read(File.ReadAllText(configPath)));
        if (doc != null)
        {
            ApplyRedirects(doc, port, publicUrl, publicGiven);
            var redirect = Sprint(doc.GetValueOrDefault("redirectUri"));
            if (redirect.Length == 0) redirect = Sprint(doc.GetValueOrDefault("redirect_uri"));
            if (redirect.Length == 0) redirect = "http://localhost/";
            if (Uri.TryCreate(redirect, UriKind.Absolute, out var parsed))
            {
                application.SecureCookies = parsed.Scheme == "https" || parsed.Host == "localhost" || parsed.Host == "127.0.0.1";
            }
        }
    }
    catch (Exception err)
    {
        Console.Error.WriteLine("cannot read configuration: " + err.Message);
    }
}
else
{
    Console.Error.WriteLine("cannot read configuration: " + configPath);
}

using var listener = Listen(port);
Console.WriteLine("oidc-caep-risc-csharp demo on port " + port);
while (listener.IsListening)
{
    HttpListenerContext context;
    try
    {
        context = listener.GetContext();
    }
    catch (HttpListenerException)
    {
        break;
    }
    catch (ObjectDisposedException)
    {
        break;
    }
    try
    {
        application.Route(context);
    }
    catch (Exception err)
    {
        Console.Error.WriteLine("demo: " + err);
        try
        {
            application.Send(context.Response, 500, Page("Error", "<h1>Something went wrong</h1><p class=\"problem\">" + Web(err.Message) + "</p><p><a href=\"/\">Home</a></p>"), "text/html; charset=utf-8", null);
        }
        catch (Exception)
        {
            try { context.Response.Abort(); } catch (Exception) { }
        }
    }
}

static HttpListener Listen(int port)
{
    var prefixes = new[] { "http://+:" + port + "/", "http://*:" + port + "/", "http://127.0.0.1:" + port + "/" };
    Exception? last = null;
    foreach (var prefix in prefixes)
    {
        var listener = new HttpListener();
        listener.Prefixes.Add(prefix);
        try
        {
            listener.Start();
            return listener;
        }
        catch (Exception err)
        {
            last = err;
            listener.Close();
        }
    }
    throw last ?? new InvalidOperationException("could not listen");
}

static (string? PublicUrl, string? Config) ParseArgs(string[] argv)
{
    string? publicUrl = null;
    string? config = null;
    for (var i = 0; i < argv.Length; i++)
    {
        var arg = argv[i];
        if (arg == "--public-url" && i + 1 < argv.Length) publicUrl = argv[++i];
        else if (arg.StartsWith("--public-url=", StringComparison.Ordinal)) publicUrl = arg["--public-url=".Length..];
        else if (arg == "--config" && i + 1 < argv.Length) config = argv[++i];
        else if (arg.StartsWith("--config=", StringComparison.Ordinal)) config = arg["--config=".Length..];
        else if (arg == "-h" || arg == "--help")
        {
            Console.Error.WriteLine("oidc-caep-risc-demo [--public-url ORIGIN] [--config PATH]");
            Environment.Exit(0);
        }
        else
        {
            Console.Error.WriteLine("unknown argument: " + arg);
            Environment.Exit(2);
        }
    }
    return (publicUrl, config);
}

static class DemoSupport
{
public static int EnvPort()
{
    var raw = (Environment.GetEnvironmentVariable("PORT") ?? "").Trim();
    if (raw.Length == 0) return 3000;
    if (!int.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out var port) || port < 1 || port > 65535 || port.ToString(CultureInfo.InvariantCulture) != raw)
    {
        return 3000;
    }
    return port;
}

public static void ApplyRedirects(Dictionary<string, object?> raw, int port, string publicUrl, bool given)
{
    var redirect = Sprint(raw.GetValueOrDefault("redirectUri"));
    if (redirect.Length == 0) redirect = Sprint(raw.GetValueOrDefault("redirect_uri"));
    var post = Sprint(raw.GetValueOrDefault("postLogoutRedirectUri"));
    if (post.Length == 0) post = Sprint(raw.GetValueOrDefault("post_logout_redirect_uri"));
    var (movedR, movedP) = RedirectsFor(redirect, post, publicUrl, given, port);
    if (raw.ContainsKey("redirectUri") || !raw.ContainsKey("redirect_uri")) raw["redirectUri"] = movedR;
    else raw["redirect_uri"] = movedR;
    if (raw.ContainsKey("postLogoutRedirectUri") || raw.ContainsKey("post_logout_redirect_uri") || post.Length > 0)
    {
        if (raw.ContainsKey("post_logout_redirect_uri") && !raw.ContainsKey("postLogoutRedirectUri")) raw["post_logout_redirect_uri"] = movedP;
        else raw["postLogoutRedirectUri"] = movedP;
    }
}

public static (string Redirect, string Post) RedirectsFor(string redirect, string post, string publicUrl, bool given, int port)
{
    if (given && publicUrl.Length > 0) return (MoveOrigin(redirect, publicUrl), MoveOrigin(post, publicUrl));
    if (port > 0) return (OnPort(redirect, port), OnPort(post, port));
    return (redirect, post);
}

public static string OnPort(string raw, int port)
{
    if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri)) return raw;
    var host = uri.Host;
    if (host != "localhost" && host != "127.0.0.1" && host != "::1") return raw;
    var builder = new UriBuilder(uri) { Port = port };
    return builder.Uri.AbsoluteUri;
}

public static string MoveOrigin(string value, string publicUrl)
{
    var baseText = publicUrl.EndsWith('/') ? publicUrl : publicUrl + "/";
    if (!Uri.TryCreate(baseText, UriKind.Absolute, out var basis)) return value;
    if (!Uri.TryCreate(value, UriKind.Absolute, out var next)) return value;
    var builder = new UriBuilder(next)
    {
        Scheme = basis.Scheme,
        Host = basis.Host,
        Port = basis.IsDefaultPort ? -1 : basis.Port,
    };
    return builder.Uri.AbsoluteUri;
}

public static string Page(string title, string body) =>
    "<!doctype html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>"
    + Web(title) + "</title><link rel=\"stylesheet\" href=\"/styles.css\"></head>\n<body><header><a href=\"/\">oidc-caep-risc demo</a></header><main>\n"
    + body + "\n</main><footer>A traditional web application signing in with OpenID Connect through oidc-caep-risc.</footer></body>\n</html>\n";

public static string Web(string value) => System.Net.WebUtility.HtmlEncode(value);

public static string Sprint(object? value) => value switch
{
    null => "",
    string text => text,
    _ => Convert.ToString(value, CultureInfo.InvariantCulture) ?? "",
};

public static int Number(object? value)
{
    if (value == null) return 0;
    try { return Convert.ToInt32(value, CultureInfo.InvariantCulture); }
    catch (Exception) { return 0; }
}

public static string ConfigDir(string path)
{
    var dir = Path.GetDirectoryName(path);
    return string.IsNullOrEmpty(dir) ? "." : dir;
}
}

sealed class DemoApp
{
    const string CookieSession = "oidc_session";
    const string CookieTxn = "oidc_txn";
    readonly object gate = new();
    readonly Dictionary<string, Session> sessions = new();
    readonly byte[] secret;
    readonly string configPath;
    readonly string publicUrl;
    readonly bool publicGiven;
    RelyingParty? rp;
    Exception? rpErr;
    bool loaded;
    SignalsReceiver? receiver;
    string receiverState = "";

    public DemoApp(byte[] secret, string configPath, string publicUrl, bool publicGiven)
    {
        this.secret = secret;
        this.configPath = configPath;
        this.publicUrl = publicUrl;
        this.publicGiven = publicGiven;
        SecureCookies = true;
    }

    public bool SecureCookies { get; set; }

    public void Route(HttpListenerContext context)
    {
        var request = context.Request;
        var path = request.Url?.AbsolutePath ?? "/";
        if (path == "/healthz")
        {
            Send(context.Response, 200, "ok", "text/plain", null);
            return;
        }
        if (path == "/styles.css" && request.HttpMethod == "GET")
        {
            Send(context.Response, 200, ReadAsset("styles.css"), "text/css; charset=utf-8", null);
            return;
        }
        if (path == "/app.js" && request.HttpMethod == "GET")
        {
            Send(context.Response, 200, ReadAsset("app.js"), "text/javascript; charset=utf-8", null);
            return;
        }
        if (path == "/" && request.HttpMethod == "GET")
        {
            Home(context);
            return;
        }
        if (path == "/login" && request.HttpMethod == "GET")
        {
            Login(context);
            return;
        }
        if (path == "/callback" && request.HttpMethod == "GET")
        {
            Callback(context);
            return;
        }
        if (path == "/logout" && request.HttpMethod == "POST")
        {
            Logout(context);
            return;
        }
        Send(context.Response, 404, Page("Not found", "<h1>Not found</h1>"), "text/html; charset=utf-8", null);
    }

    void Home(HttpListenerContext context)
    {
        var (_, sess) = SessionOf(context.Request);
        string problem = "";
        RelyingParty? party;
        try
        {
            party = Open();
        }
        catch (Exception err)
        {
            party = null;
            problem = "The relying party is not configured yet: " + err.Message + ". Run scripts/configure_iya_sts.py.";
        }
        if (sess?.Login != null)
        {
            var login = sess.Login;
            var who = login.PreferredUsername;
            if (string.IsNullOrEmpty(who)) who = login.Email;
            if (string.IsNullOrEmpty(who)) who = login.Subject;
            var rows = "";
            foreach (var row in new[]
            {
                ("Subject", login.Subject),
                ("Issuer", login.Issuer),
                ("Email", login.Email ?? ""),
                ("Name", login.Name ?? ""),
                ("Username", login.PreferredUsername ?? ""),
            })
            {
                if (row.Item2.Length == 0) continue;
                rows += "<tr><th>" + Web(row.Item1) + "</th><td>" + Web(row.Item2) + "</td></tr>";
            }
            var body = "<h1>Signed in as " + Web(who ?? "") + "</h1><table class=\"facts\">" + rows
                + "</table><p><small>The access token and the refresh token stay in this process. This page does not show them.</small></p><p><small>Shared Signals: "
                + Web(State()) + "</small></p><form method=\"post\" action=\"/logout\"><button type=\"submit\">Sign out</button></form>";
            Send(context.Response, 200, Page("Signed in", body), "text/html; charset=utf-8", null);
            return;
        }
        var issuer = "";
        if (party != null)
        {
            var text = Sprint(party.Metadata.GetValueOrDefault("issuer"));
            if (text.Length > 0) issuer = " of " + Web(text);
        }
        var problemHtml = problem.Length == 0 ? "" : "<p class=\"problem\">" + Web(problem) + "</p>";
        var signedOut = "<h1>Sign in with OpenID Connect</h1>" + problemHtml
            + "<p>This application is a confidential client" + issuer
            + ". It sends the browser to the authorization endpoint (Authorization Code, PKCE S256) and takes the tokens on the back channel.</p><p class=\"buttons\"><a class=\"button primary\" href=\"/login\">Sign in with OpenID Connect</a></p>";
        Send(context.Response, 200, Page("Sign in", signedOut), "text/html; charset=utf-8", null);
    }

    void Login(HttpListenerContext context)
    {
        RelyingParty party;
        try
        {
            party = Open();
        }
        catch (Exception err)
        {
            Send(context.Response, 500, Page("Error", "<h1>Something went wrong</h1><p class=\"problem\">" + Web(err.Message) + "</p>"), "text/html; charset=utf-8", null);
            return;
        }
        RelyingParty.Transaction request;
        try
        {
            request = party.Authorize();
        }
        catch (Exception err)
        {
            Send(context.Response, 500, Page("Error", "<h1>Something went wrong</h1><p class=\"problem\">" + Web(err.Message) + "</p>"), "text/html; charset=utf-8", null);
            return;
        }
        var txn = new Dictionary<string, string>
        {
            ["state"] = request.State ?? "",
            ["nonce"] = request.Nonce ?? "",
            ["code_verifier"] = request.CodeVerifier ?? "",
            ["redirect_uri"] = request.RedirectUri ?? "",
        };
        Redirect(context.Response, 302, request.Url ?? "/", new[] { Cookie(CookieTxn, Seal(txn), "/callback", 600) });
    }

    void Callback(HttpListenerContext context)
    {
        var clear = Cookie(CookieTxn, "", "/callback", 0);
        RelyingParty party;
        try
        {
            party = Open();
        }
        catch (Exception err)
        {
            Send(context.Response, 500, Page("Error", "<h1>Something went wrong</h1><p class=\"problem\">" + Web(err.Message) + "</p>"), "text/html; charset=utf-8", new[] { clear });
            return;
        }
        var query = new Dictionary<string, string>();
        if (context.Request.QueryString.Count > 0)
        {
            foreach (var key in context.Request.QueryString.AllKeys)
            {
                if (key == null) continue;
                query[key] = context.Request.QueryString[key] ?? "";
            }
        }
        var txn = Unseal(CookieValue(context.Request, CookieTxn));
        if (txn == null)
        {
            Send(context.Response, 400, Page("Sign-in failed", "<h1>Sign-in failed</h1><p class=\"problem\">validation: this callback is not a sign-in this browser started</p><p><a href=\"/\">Start again</a></p>"), "text/html; charset=utf-8", new[] { clear });
            return;
        }
        var request = new RelyingParty.Transaction
        {
            State = txn.GetValueOrDefault("state"),
            Nonce = txn.GetValueOrDefault("nonce"),
            CodeVerifier = txn.GetValueOrDefault("code_verifier"),
            RedirectUri = txn.GetValueOrDefault("redirect_uri"),
        };
        RelyingParty.Login login;
        try
        {
            login = party.Complete(query, request);
        }
        catch (Exception err)
        {
            var what = err is OidcError oidc ? oidc.Code + ": " + oidc.Message : err.Message;
            Send(context.Response, 400, Page("Sign-in failed", "<h1>Sign-in failed</h1><p class=\"problem\">" + Web(what) + "</p><p><a href=\"/\">Start again</a></p>"), "text/html; charset=utf-8", new[] { clear });
            return;
        }
        var sid = Codec.RandomToken();
        SignalsReceiver? current;
        lock (gate)
        {
            sessions[sid] = new Session(login, DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 8 * 3600);
            current = receiver;
        }
        current?.Track(SessionIndex.TrackedFromLogin(sid, login, null));
        Redirect(context.Response, 303, "/", new[] { clear, Cookie(CookieSession, sid, "/", 8 * 3600) });
    }

    void Logout(HttpListenerContext context)
    {
        var (sid, _) = SessionOf(context.Request);
        if (sid.Length > 0)
        {
            SignalsReceiver? current;
            lock (gate)
            {
                sessions.Remove(sid);
                current = receiver;
            }
            current?.Untrack(sid);
        }
        Redirect(context.Response, 303, "/", new[] { Cookie(CookieSession, "", "/", 0) });
    }

    RelyingParty Open()
    {
        lock (gate)
        {
            if (loaded)
            {
                if (rpErr != null) throw rpErr;
                return rp!;
            }
            loaded = true;
            try
            {
                rp = Load();
            }
            catch (Exception err)
            {
                rpErr = err;
                throw;
            }
            StartReceiver(rp);
            return rp;
        }
    }

    RelyingParty Load()
    {
        var raw = File.ReadAllText(configPath);
        var doc = Jsons.Map(Jsons.Read(raw)) ?? throw new OidcError("config", "the configuration must be a JSON object");
        var metadataFile = Environment.GetEnvironmentVariable("OIDC_METADATA_FILE");
        if (!string.IsNullOrEmpty(metadataFile))
        {
            doc["metadataFile"] = metadataFile;
            doc.Remove("metadataUrl");
            doc.Remove("issuer");
        }
        ApplyRedirects(doc, EnvPort(), publicUrl, publicGiven);
        if (doc.GetValueOrDefault("signals") is false)
        {
            receiverState = "not configured (signals are off)";
        }
        else if (doc.GetValueOrDefault("ssf") is not Dictionary<string, object?> ssf || Sprint(ssf.GetValueOrDefault("transmitter")).Length == 0)
        {
            receiverState = "not configured (no ssf block in the configuration file)";
        }
        else
        {
            receiverState = "starting";
        }
        var resolved = Config.ResolveConfig(doc, ConfigDir(configPath));
        return IyaSec.Oidc.RelyingParty.Create(resolved);
    }

    void StartReceiver(RelyingParty party)
    {
        var cfg = party.ConfigMap;
        if (cfg.GetValueOrDefault("signals") is false || cfg.GetValueOrDefault("ssf") == null || receiver != null)
        {
            if (cfg.GetValueOrDefault("signals") is false) receiverState = "not configured (signals are off)";
            return;
        }
        if (cfg.GetValueOrDefault("ssf") is not Dictionary<string, object?> ssf) return;
        var transmitter = Sprint(ssf.GetValueOrDefault("transmitter"));
        if (transmitter.Length == 0) return;
        var interval = Number(ssf.GetValueOrDefault("pollIntervalMs"));
        if (interval == 0) interval = 5000;
        SignalsReceiver built;
        try
        {
            built = SignalsReceiver.New(transmitter, (ids, _) =>
            {
                lock (gate)
                {
                    foreach (var id in ids) sessions.Remove(id);
                }
            })
                .WithTls(party.Tls())
                .WithHeaders(() => SignalHeaders(party))
                .WithDescription("oidc-caep-risc-csharp demo (" + Sprint(cfg.GetValueOrDefault("clientId")) + ")")
                .WithPollIntervalMs(interval)
                .Build();
        }
        catch (Exception err)
        {
            receiverState = "not running: " + err.Message;
            Console.Error.WriteLine("ssf: the receiver did not start: " + err);
            return;
        }
        receiver = built;
        try
        {
            built.Start();
        }
        catch (Exception err)
        {
            receiver = null;
            receiverState = "not running: " + err.Message;
            Console.Error.WriteLine("ssf: the receiver did not start: " + err);
            return;
        }
        var streamId = built.Stream == null ? "" : Sprint(built.Stream.GetValueOrDefault("stream_id"));
        receiverState = "polling stream " + streamId + " at " + transmitter;
    }

    Dictionary<string, string> SignalHeaders(RelyingParty party)
    {
        try
        {
            var access = party.ClientCredentials("ssf.manage");
            return new Dictionary<string, string> { ["authorization"] = "Bearer " + access.AccessToken };
        }
        catch (Exception)
        {
            return new Dictionary<string, string>();
        }
    }

    string State()
    {
        lock (gate) return receiverState;
    }

    (string Sid, Session? Session) SessionOf(HttpListenerRequest request)
    {
        var sid = CookieValue(request, CookieSession);
        lock (gate)
        {
            if (!sessions.TryGetValue(sid, out var sess)) return ("", null);
            if (sess.Expires <= DateTimeOffset.UtcNow.ToUnixTimeSeconds())
            {
                sessions.Remove(sid);
                return ("", null);
            }
            return (sid, sess);
        }
    }

    string Cookie(string name, string value, string path, int maxAge)
    {
        var parts = new List<string> { name + "=" + value, "Path=" + path, "HttpOnly", "SameSite=Lax" };
        if (SecureCookies) parts.Add("Secure");
        if (maxAge >= 0) parts.Add("Max-Age=" + maxAge.ToString(CultureInfo.InvariantCulture));
        return string.Join("; ", parts);
    }

    public void Send(HttpListenerResponse response, int status, string body, string contentType, IEnumerable<string>? cookies)
    {
        var bytes = Encoding.UTF8.GetBytes(body);
        response.StatusCode = status;
        response.ContentType = contentType;
        response.Headers["Cache-Control"] = "no-store";
        response.Headers["Referrer-Policy"] = "no-referrer";
        response.Headers["X-Content-Type-Options"] = "nosniff";
        response.Headers["X-Frame-Options"] = "DENY";
        response.Headers["Content-Security-Policy"] = "default-src 'none'; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
        if (cookies != null)
        {
            foreach (var cookie in cookies) response.AppendHeader("Set-Cookie", cookie);
        }
        response.ContentLength64 = bytes.Length;
        response.OutputStream.Write(bytes, 0, bytes.Length);
        response.OutputStream.Close();
        response.Close();
    }

    void Redirect(HttpListenerResponse response, int status, string location, IEnumerable<string> cookies)
    {
        response.StatusCode = status;
        response.Headers["Location"] = location;
        response.Headers["Cache-Control"] = "no-store";
        response.Headers["Referrer-Policy"] = "no-referrer";
        foreach (var cookie in cookies) response.AppendHeader("Set-Cookie", cookie);
        response.ContentLength64 = 0;
        response.OutputStream.Close();
        response.Close();
    }

    string Seal(Dictionary<string, string> value)
    {
        var raw = JsonSerializer.Serialize(value);
        var body = Codec.B64UrlEncode(Encoding.UTF8.GetBytes(raw));
        return body + "." + Mac(body);
    }

    Dictionary<string, string>? Unseal(string token)
    {
        var dot = token.IndexOf('.');
        if (token.Length == 0 || dot < 0) return null;
        var body = token[..dot];
        var tag = token[(dot + 1)..];
        var expected = Encoding.ASCII.GetBytes(Mac(body));
        var actual = Encoding.ASCII.GetBytes(tag);
        if (expected.Length != actual.Length || !CryptographicOperations.FixedTimeEquals(expected, actual)) return null;
        try
        {
            var raw = Codec.B64UrlDecode(body, "transaction");
            return JsonSerializer.Deserialize<Dictionary<string, string>>(raw);
        }
        catch (Exception)
        {
            return null;
        }
    }

    string Mac(string value)
    {
        var sum = HMACSHA256.HashData(secret, Encoding.UTF8.GetBytes(value));
        return Codec.B64UrlEncode(sum);
    }

    static string CookieValue(HttpListenerRequest request, string name)
    {
        var cookies = request.Cookies;
        if (cookies == null) return "";
        var cookie = cookies[name];
        return cookie?.Value ?? "";
    }

    static string ReadAsset(string name)
    {
        foreach (var path in new[]
        {
            Path.Combine("demo", "public", name),
            Path.Combine("public", name),
            Path.Combine(AppContext.BaseDirectory, "public", name),
            Path.Combine(AppContext.BaseDirectory, "demo", "public", name),
        })
        {
            if (File.Exists(path)) return File.ReadAllText(path);
        }
        return "";
    }

    sealed class Session
    {
        public Session(RelyingParty.Login login, long expires)
        {
            Login = login;
            Expires = expires;
        }

        public RelyingParty.Login Login { get; }
        public long Expires { get; }
    }
}
