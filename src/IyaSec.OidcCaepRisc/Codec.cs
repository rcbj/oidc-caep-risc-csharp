// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using System.Text;

namespace IyaSec.Oidc;

/// <summary>Base64url, PKCE S256, and form encoding.</summary>
public static class Codec
{
    public static string B64UrlEncode(byte[] data) => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] B64UrlDecode(string? value, string what)
    {
        if (value == null || !System.Text.RegularExpressions.Regex.IsMatch(value, "^[A-Za-z0-9_-]*$"))
        {
            throw new ArgumentException(what + " is not base64url");
        }
        var padded = value.Length % 4 == 0 ? value : value + new string('=', 4 - (value.Length % 4));
        return Convert.FromBase64String(padded.Replace('-', '+').Replace('_', '/'));
    }

    public static string RandomToken()
    {
        var buf = new byte[32];
        RandomNumberGenerator.Fill(buf);
        return B64UrlEncode(buf);
    }

    public static string CodeChallengeS256(string verifier) => B64UrlEncode(Sha256(Encoding.UTF8.GetBytes(verifier)));

    public static byte[] Sha256(byte[] data) => SHA256.HashData(data);

    public static byte[] Sha384(byte[] data) => SHA384.HashData(data);

    public static byte[] Sha512(byte[] data) => SHA512.HashData(data);

    public static string Hex(byte[] data) => Convert.ToHexString(data).ToLowerInvariant();

    public static string FormBody(IEnumerable<KeyValuePair<string, object?>> fields)
    {
        var outText = new StringBuilder();
        foreach (var entry in fields)
        {
            if (outText.Length > 0) outText.Append('&');
            outText.Append(QuotePlus(entry.Key)).Append('=').Append(QuotePlus(entry.Value == null ? "" : Convert.ToString(entry.Value, System.Globalization.CultureInfo.InvariantCulture) ?? ""));
        }
        return outText.ToString();
    }

    public static string FormEncode(string? value)
    {
        var outText = new StringBuilder();
        foreach (var b in Encoding.UTF8.GetBytes(value ?? ""))
        {
            int c = b;
            if (Unreserved(c) || c == '!' || c == '~' || c == '*' || c == '\'' || c == '(' || c == ')') outText.Append((char)c);
            else if (c == ' ') outText.Append('+');
            else Percent(outText, c);
        }
        return outText.ToString();
    }

    public static string QuotePlus(string value)
    {
        var outText = new StringBuilder();
        foreach (var b in Encoding.UTF8.GetBytes(value))
        {
            int c = b;
            if (c == ' ') outText.Append('+');
            else if (Unreserved(c) || c == '/') outText.Append((char)c);
            else Percent(outText, c);
        }
        return outText.ToString();
    }

    static bool Unreserved(int c) => (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';

    static void Percent(StringBuilder outText, int c)
    {
        outText.Append('%');
        outText.Append(Convert.ToString(c >> 4, 16).ToUpperInvariant());
        outText.Append(Convert.ToString(c & 0xf, 16).ToUpperInvariant());
    }
}
