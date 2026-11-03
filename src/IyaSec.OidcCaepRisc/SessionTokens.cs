// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Collections.Concurrent;

namespace IyaSec.Oidc;

/// <summary>The tokens of one completed sign-in, kept under the application's session identifier.</summary>
public sealed class SessionTokens
{
    /// <summary>The ID token's <c>sub</c>; a refreshed ID token must name the same subject.</summary>
    public string Subject { get; set; } = "";
    /// <summary>The access token.</summary>
    public string AccessToken { get; set; } = "";
    /// <summary><c>Bearer</c>, or <c>DPoP</c> when the access token is bound to this relying party's DPoP key.</summary>
    public string TokenType { get; set; } = "";
    /// <summary>The refresh token, when the provider issued one.</summary>
    public string? RefreshToken { get; set; }
    /// <summary>The latest ID token.</summary>
    public string IdToken { get; set; } = "";
    /// <summary>When the access token expires (UTC), when the provider said.</summary>
    public DateTime? ExpiresAt { get; set; }
    /// <summary>The granted scope, when the provider said.</summary>
    public string? Scope { get; set; }
}

/// <summary>
/// Where a relying party keeps sign-in tokens per session. The default is
/// <see cref="MemorySessionTokenStore"/>; an application that runs several processes replaces it
/// with a shared store.
/// </summary>
public interface ISessionTokenStore
{
    /// <summary>The tokens kept for a session, or null.</summary>
    SessionTokens? Get(string sessionId);

    /// <summary>Keeps (or replaces) the tokens for a session.</summary>
    void Set(string sessionId, SessionTokens tokens);

    /// <summary>Forgets a session's tokens. Removing an unknown session does nothing.</summary>
    void Remove(string sessionId);
}

/// <summary>The in-memory session token store, bounded to a number of sessions (oldest dropped first).</summary>
public sealed class MemorySessionTokenStore : ISessionTokenStore
{
    readonly ConcurrentDictionary<string, (long Order, SessionTokens Tokens)> entries = new(StringComparer.Ordinal);
    readonly int max;
    long order;

    /// <summary>A store holding at most <paramref name="maxSessions"/> sessions.</summary>
    public MemorySessionTokenStore(int maxSessions = 100_000)
    {
        max = maxSessions <= 0 ? 100_000 : maxSessions;
    }

    /// <inheritdoc />
    public SessionTokens? Get(string sessionId) => entries.TryGetValue(sessionId, out var entry) ? entry.Tokens : null;

    /// <inheritdoc />
    public void Set(string sessionId, SessionTokens tokens)
    {
        entries[sessionId] = (Interlocked.Increment(ref order), tokens);
        if (entries.Count <= max) return;
        foreach (var oldest in entries.OrderBy(entry => entry.Value.Order).Take(entries.Count - max).Select(entry => entry.Key).ToList())
        {
            entries.TryRemove(oldest, out _);
        }
    }

    /// <inheritdoc />
    public void Remove(string sessionId) => entries.TryRemove(sessionId, out _);
}
