// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

namespace IyaSec.Oidc;

/// <summary>A failure from configuration, discovery, the protocol, validation, a signature, or Shared Signals.</summary>
public sealed class OidcError : Exception
{
    public string Code { get; }
    public string? OauthError { get; }

    public OidcError(string code, string message, Exception? cause = null, string? oauthError = null)
        : base(message, cause)
    {
        Code = code;
        OauthError = oauthError;
    }
}
