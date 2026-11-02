// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace IyaSec.Oidc;

/// <summary>One back-channel request. TLS is verified. Redirects are not followed.</summary>
public static class Http
{
    public const int MaxBytes = 2 * 1024 * 1024;
    public const int TimeoutSeconds = 15;

    static readonly HttpClient Plain = Build(null);

    public readonly record struct Result(int Status, string ContentType, string Body);

    public static Result Send(string url, string method, IReadOnlyDictionary<string, string>? headers, byte[]? body, IReadOnlyDictionary<string, string>? tls, string code)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || (uri.Scheme != "http" && uri.Scheme != "https") || string.IsNullOrEmpty(uri.Host))
        {
            throw new OidcError(code, url + " is not an http(s) URL");
        }
        var client = Client(tls, code, url);
        using var request = new HttpRequestMessage(new HttpMethod(method), uri);
        request.Version = HttpVersion.Version11;
        request.VersionPolicy = HttpVersionPolicy.RequestVersionOrLower;
        request.Headers.TryAddWithoutValidation("Connection", "close");
        if (headers != null)
        {
            foreach (var entry in headers)
            {
                if (string.IsNullOrEmpty(entry.Key) || entry.Value == null) continue;
                if (entry.Key.Equals("content-length", StringComparison.OrdinalIgnoreCase) || entry.Key.Equals("host", StringComparison.OrdinalIgnoreCase)) continue;
                if (entry.Key.Equals("content-type", StringComparison.OrdinalIgnoreCase)) continue;
                request.Headers.TryAddWithoutValidation(entry.Key, entry.Value);
            }
        }
        if (body != null)
        {
            var type = "application/octet-stream";
            if (headers != null)
            {
                foreach (var entry in headers)
                {
                    if (entry.Key.Equals("content-type", StringComparison.OrdinalIgnoreCase)) type = entry.Value;
                }
            }
            request.Content = new ByteArrayContent(body);
            request.Content.Headers.ContentType = System.Net.Http.Headers.MediaTypeHeaderValue.Parse(type);
        }
        try
        {
            using var response = client.Send(request, HttpCompletionOption.ResponseHeadersRead);
            var raw = ReadLimited(response, url, code);
            var contentType = response.Content.Headers.ContentType?.ToString() ?? "";
            return new Result((int)response.StatusCode, contentType, Encoding.UTF8.GetString(raw));
        }
        catch (OidcError)
        {
            throw;
        }
        catch (TaskCanceledException err)
        {
            throw new OidcError(code, url + " did not answer within " + TimeoutSeconds + " s", err);
        }
        catch (Exception err)
        {
            var message = err.Message ?? "";
            if (message.Contains("timed out", StringComparison.OrdinalIgnoreCase) || message.Contains("timeout", StringComparison.OrdinalIgnoreCase))
            {
                throw new OidcError(code, url + " did not answer within " + TimeoutSeconds + " s", err);
            }
            throw new OidcError(code, url + ": " + err.Message, err);
        }
    }

    static byte[] ReadLimited(HttpResponseMessage response, string url, string code)
    {
        using var stream = response.Content.ReadAsStream();
        using var memory = new MemoryStream();
        var buffer = new byte[8192];
        while (true)
        {
            int n = stream.Read(buffer, 0, buffer.Length);
            if (n <= 0) break;
            if (memory.Length + n > MaxBytes) throw new OidcError(code, url + " answered more than " + MaxBytes + " bytes");
            memory.Write(buffer, 0, n);
        }
        return memory.ToArray();
    }

    static HttpClient Client(IReadOnlyDictionary<string, string>? tls, string code, string url)
    {
        var ca = tls != null && tls.TryGetValue("ca", out var pem) ? pem : null;
        if (string.IsNullOrEmpty(ca)) return Plain;
        try
        {
            return Build(ca);
        }
        catch (OidcError)
        {
            throw;
        }
        catch (Exception err)
        {
            throw new OidcError(code, url + ": " + err.Message, err);
        }
    }

    static HttpClient Build(string? ca)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromSeconds(TimeoutSeconds),
            PooledConnectionLifetime = TimeSpan.Zero,
        };
        if (!string.IsNullOrEmpty(ca))
        {
            X509Certificate2Collection extra;
            try
            {
                extra = LoadPem(ca);
            }
            catch (Exception err)
            {
                throw new OidcError("config", "the configured tlsCa is not a PEM trust anchor", err);
            }
            if (extra.Count == 0) throw new OidcError("config", "the configured tlsCa is not a PEM trust anchor");
            handler.SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (sender, cert, chain, errors) =>
                {
                    if (errors == SslPolicyErrors.None) return true;
                    if (cert == null) return false;
                    using var built = new X509Chain();
                    built.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                    built.ChainPolicy.CustomTrustStore.AddRange(extra);
                    built.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    return built.Build(new X509Certificate2(cert));
                },
            };
        }
        return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(TimeoutSeconds) };
    }

    static X509Certificate2Collection LoadPem(string pem)
    {
        var store = new X509Certificate2Collection();
        var parts = pem.Split("-----END CERTIFICATE-----", StringSplitOptions.RemoveEmptyEntries);
        foreach (var part in parts)
        {
            var block = part.Trim();
            if (!block.Contains("BEGIN CERTIFICATE", StringComparison.Ordinal)) continue;
            store.ImportFromPem(block + "\n-----END CERTIFICATE-----\n");
        }
        return store;
    }
}
