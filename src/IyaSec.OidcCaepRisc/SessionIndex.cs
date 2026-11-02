// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

namespace IyaSec.Oidc;

/// <summary>Which local sessions belong to which person and which provider session.</summary>
public sealed class SessionIndex
{
    readonly Dictionary<string, Dictionary<string, object?>> sessions = new();
    readonly int max;

    public SessionIndex(int maxSessions = 100_000)
    {
        max = maxSessions;
    }

    public void Add(IReadOnlyDictionary<string, object?> session)
    {
        var localId = Convert.ToString(session.GetValueOrDefault("local_id")) ?? "";
        if (sessions.Count >= max && !sessions.ContainsKey(localId))
        {
            var now = NowSec();
            foreach (var key in sessions.Keys.ToList())
            {
                var expires = sessions[key].GetValueOrDefault("expires_at");
                if (expires != null && Stamp(expires) <= now) sessions.Remove(key);
            }
            while (sessions.Count >= max && sessions.Count > 0) sessions.Remove(sessions.Keys.First());
        }
        var stored = new Dictionary<string, object?>();
        foreach (var entry in session) stored[entry.Key] = entry.Value;
        if (stored.GetValueOrDefault("email") is string email) stored["email"] = email.ToLowerInvariant();
        sessions[localId] = stored;
    }

    public void Remove(string localId) => sessions.Remove(localId);

    public List<string> ByPerson(string person) => Find(session => person.Equals(session.GetValueOrDefault("person")));

    public List<string> ByEmail(string email)
    {
        var wanted = email.ToLowerInvariant();
        return Find(session => wanted.Equals(session.GetValueOrDefault("email")));
    }

    public List<string> ByIdpSession(string idpSession) => Find(session => idpSession.Equals(session.GetValueOrDefault("idp_session")));

    public static Dictionary<string, object?> TrackedFromLogin(string localId, RelyingParty.Login login, DateTime? expiresAt)
    {
        var session = new Dictionary<string, object?>
        {
            ["local_id"] = localId,
            ["person"] = login.Subject,
        };
        if (login.Email != null) session["email"] = login.Email;
        if (login.Sid != null) session["idp_session"] = login.Sid;
        if (expiresAt != null) session["expires_at"] = expiresAt;
        return session;
    }

    List<string> Find(Func<Dictionary<string, object?>, bool> match)
    {
        var now = NowSec();
        var output = new List<string>();
        foreach (var key in sessions.Keys.ToList())
        {
            if (!sessions.TryGetValue(key, out var value)) continue;
            var expires = value.GetValueOrDefault("expires_at");
            if (expires != null && Stamp(expires) <= now)
            {
                sessions.Remove(key);
                continue;
            }
            if (match(value)) output.Add(key);
        }
        return output;
    }

    static double NowSec() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0;

    static double Stamp(object value)
    {
        if (value is DateTime date)
        {
            var specified = date.Kind == DateTimeKind.Unspecified ? DateTime.SpecifyKind(date, DateTimeKind.Utc) : date;
            return new DateTimeOffset(specified).ToUnixTimeMilliseconds() / 1000.0;
        }
        if (value is DateTimeOffset stamp) return stamp.ToUnixTimeMilliseconds() / 1000.0;
        if (value is byte or short or int or long or float or double or decimal) return Config.AsDouble(value);
        return double.Parse(Convert.ToString(value)!, System.Globalization.CultureInfo.InvariantCulture);
    }
}
