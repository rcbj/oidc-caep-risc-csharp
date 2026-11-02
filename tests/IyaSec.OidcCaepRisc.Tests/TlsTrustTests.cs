// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using IyaSec.Oidc;
using Xunit;

namespace IyaSec.OidcCaepRisc.Tests;

// iya-sts's TLS listener presents leaf, TLS issuing CA, intermediate and root,
// and GET /tls/server-certificate answers the same chain, which the setup script
// saves where tlsCa names it. The library's validation callback answers a chain
// error by building to that file, so it must check the listener's name itself.
// The server below sends only its leaf, so the chain can be built only through
// the file.
public class TlsTrustTests
{
    sealed class Chain
    {
        public X509Certificate2 Leaf = null!;
        public string Pem = "";
        // The CA certificates (issuing, intermediate, root), public, as a server could send them.
        public X509Certificate2Collection Authorities = new();
        public string AuthoritiesPem = "";
    }

    static Chain MakeChain(string name, Action<SubjectAlternativeNameBuilder> names)
    {
        var now = DateTimeOffset.UtcNow;
        X509Certificate2 Ca(string cn, X509Certificate2? issuer, RSA key)
        {
            var req = new CertificateRequest("CN=" + cn, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
            if (issuer == null) return req.CreateSelfSigned(now.AddDays(-1), now.AddDays(30));
            req.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuer, true, false));
            return req.Create(issuer, now.AddDays(-1), now.AddDays(29), RandomNumberGenerator.GetBytes(12));
        }
        using var rootKey = RSA.Create(2048);
        using var midKey = RSA.Create(2048);
        using var issuingKey = RSA.Create(2048);
        using var root = Ca(name + " Root CA", null, rootKey);
        using var mid = Ca(name + " Intermediate CA", root, midKey);
        using var midWithKey = mid.CopyWithPrivateKey(midKey);
        using var issuing = Ca(name + " TLS Issuing CA", midWithKey, issuingKey);
        using var issuingWithKey = issuing.CopyWithPrivateKey(issuingKey);
        var leafKey = RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=" + name, leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        names(san);
        leafReq.CertificateExtensions.Add(san.Build());
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        leafReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
        leafReq.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuingWithKey, true, false));
        using var leaf = leafReq.Create(issuingWithKey, now.AddDays(-1), now.AddDays(28), RandomNumberGenerator.GetBytes(12));
        using var leafWithKey = leaf.CopyWithPrivateKey(leafKey);
        string Pem(X509Certificate2 cert) => new string(PemEncoding.Write("CERTIFICATE", cert.RawData)) + "\n";
        return new Chain
        {
            Leaf = new X509Certificate2(leafWithKey.Export(X509ContentType.Pkcs12)),
            Pem = Pem(leaf) + Pem(issuing) + Pem(mid) + Pem(root),
            Authorities = new X509Certificate2Collection
            {
                new X509Certificate2(issuing.RawData),
                new X509Certificate2(mid.RawData),
                new X509Certificate2(root.RawData),
            },
            AuthoritiesPem = Pem(issuing) + Pem(mid) + Pem(root),
        };
    }

    // The names an iya-sts TLS listener certificate carries.
    static void IyaStsNames(SubjectAlternativeNameBuilder san)
    {
        san.AddDnsName("localhost");
        san.AddDnsName("sts");
        san.AddDnsName("sts-mock");
        san.AddDnsName("sts.example.com");
        san.AddIpAddress(IPAddress.Loopback);
    }

    // A one-connection-at-a-time HTTPS server that presents the leaf, and the
    // extra certificates after it when any are given.
    sealed class TlsServer : IDisposable
    {
        readonly TcpListener _tcp = new(IPAddress.Loopback, 0);
        public int Port => ((IPEndPoint)_tcp.LocalEndpoint).Port;

        public TlsServer(X509Certificate2 leaf, X509Certificate2Collection? sent = null)
        {
            var context = SslStreamCertificateContext.Create(leaf, sent ?? new X509Certificate2Collection(), offline: true);
            _tcp.Start();
            new Thread(() =>
            {
                while (true)
                {
                    TcpClient client;
                    try { client = _tcp.AcceptTcpClient(); }
                    catch { return; }
                    try
                    {
                        using (client)
                        using (var tls = new SslStream(client.GetStream()))
                        {
                            tls.AuthenticateAsServer(new SslServerAuthenticationOptions { ServerCertificateContext = context });
                            var head = new StringBuilder();
                            var one = new byte[1];
                            while (!head.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal) && tls.Read(one, 0, 1) == 1)
                                head.Append((char)one[0]);
                            var bytes = Encoding.UTF8.GetBytes("ok");
                            tls.Write(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: " + bytes.Length + "\r\nconnection: close\r\n\r\n"));
                            tls.Write(bytes);
                        }
                    }
                    catch { }
                }
            }) { IsBackground = true }.Start();
        }

        public void Dispose() => _tcp.Stop();
    }

    static OidcError? Fetch(Chain chain, string host, string? caPem = null, X509Certificate2? leaf = null, X509Certificate2Collection? sent = null)
    {
        using var server = new TlsServer(leaf ?? chain.Leaf, sent);
        try
        {
            var answer = Http.Send("https://" + host + ":" + server.Port + "/", "GET", new Dictionary<string, string>(), null, new Dictionary<string, string> { ["ca"] = caPem ?? chain.Pem }, "discovery");
            Assert.Equal(200, answer.Status);
            Assert.Equal("ok", answer.Body);
            return null;
        }
        catch (OidcError err) { return err; }
    }

    [Fact]
    public void TheWholeChainFileIsTheTrustStore()
    {
        var chain = MakeChain("sts", IyaStsNames);
        Assert.Null(Fetch(chain, "127.0.0.1"));
    }

    // The first block of the file is the TLS Issuing CA and the root is the
    // last: the listener sends only its leaf, so it is accepted only when every
    // block of the file is read.
    [Fact]
    public void EveryPemBlockOfTheFileIsRead()
    {
        var chain = MakeChain("sts", IyaStsNames);
        Assert.Null(Fetch(chain, "127.0.0.1", chain.AuthoritiesPem));
    }

    // No pin shortcut: the CA certificates are public, so a server may send its
    // own leaf, carrying the right names, followed by the real issuing,
    // intermediate and root. It does not chain to the file and is refused.
    [Fact]
    public void AForgedLeafFollowedByTheRealAuthoritiesIsRefused()
    {
        var chain = MakeChain("sts", IyaStsNames);
        var forged = MakeChain("sts", IyaStsNames);
        var err = Fetch(chain, "127.0.0.1", chain.Pem, forged.Leaf, chain.Authorities);
        Assert.NotNull(err);
        Assert.Equal("discovery", err!.Code);
        err = Fetch(chain, "localhost", chain.Pem, forged.Leaf, chain.Authorities);
        Assert.NotNull(err);
    }

    [Fact]
    public void AChainFromAnotherRootIsRefused()
    {
        var chain = MakeChain("sts", IyaStsNames);
        var other = MakeChain("other", IyaStsNames);
        var err = Fetch(chain, "127.0.0.1", other.Pem);
        Assert.NotNull(err);
        Assert.Equal("discovery", err!.Code);
    }

    // The chain is good; the name is not. The custom callback replaces the
    // platform's decision, name check included, so it has to refuse this itself.
    [Fact]
    public void AListenerNamingAnotherHostIsRefusedThoughItChainsToTheAnchor()
    {
        var chain = MakeChain("sts", san => san.AddDnsName("other.example.com"));
        var err = Fetch(chain, "localhost");
        Assert.NotNull(err);
        Assert.Equal("discovery", err!.Code);
    }

    [Fact]
    public void AnIpLiteralMustMatchAnIpAddressSan()
    {
        var chain = MakeChain("sts", san => san.AddDnsName("localhost"));
        Assert.NotNull(Fetch(chain, "127.0.0.1"));
    }

    [Fact]
    public void TheIyaStsListenerIsAcceptedByItsDnsNameAndByItsIpAddress()
    {
        var chain = MakeChain("sts", IyaStsNames);
        Assert.Null(Fetch(chain, "localhost"));
        Assert.Null(Fetch(chain, "127.0.0.1"));
    }

    [Fact]
    public void TheIyaStsListenerIsRefusedUnderANameItDoesNotCarry()
    {
        var chain = MakeChain("sts", san => { san.AddDnsName("sts.example.com"); san.AddIpAddress(IPAddress.Parse("10.9.8.7")); });
        Assert.NotNull(Fetch(chain, "localhost"));
        Assert.NotNull(Fetch(chain, "127.0.0.1"));
    }
}
