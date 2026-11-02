// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

namespace IyaSec.Oidc;

/// <summary>CAEP, RISC, and SSF event types, and what an event's subject names.</summary>
public static class Events
{
    const string Caep = "https://schemas.openid.net/secevent/caep/event-type/";
    const string Risc = "https://schemas.openid.net/secevent/risc/event-type/";
    const string Ssf = "https://schemas.openid.net/secevent/ssf/event-type/";

    public static readonly Dictionary<string, string> Event = new();
    public static readonly List<string> CaepEvents = new();
    public static readonly List<string> RiscEvents = new();
    public static readonly IReadOnlyList<string> DefaultEventsRequested;
    public static readonly IReadOnlyList<string> DefaultEndingEvents;

    static Events()
    {
        Put("sessionRevoked", Caep + "session-revoked");
        Put("tokenClaimsChange", Caep + "token-claims-change");
        Put("credentialChange", Caep + "credential-change");
        Put("assuranceLevelChange", Caep + "assurance-level-change");
        Put("deviceComplianceChange", Caep + "device-compliance-change");
        Put("sessionEstablished", Caep + "session-established");
        Put("sessionPresented", Caep + "session-presented");
        Put("riskLevelChange", Caep + "risk-level-change");
        Put("accountCredentialChangeRequired", Risc + "account-credential-change-required");
        Put("accountPurged", Risc + "account-purged");
        Put("accountDisabled", Risc + "account-disabled");
        Put("accountEnabled", Risc + "account-enabled");
        Put("identifierChanged", Risc + "identifier-changed");
        Put("identifierRecycled", Risc + "identifier-recycled");
        Put("credentialCompromise", Risc + "credential-compromise");
        Put("optIn", Risc + "opt-in");
        Put("optOutInitiated", Risc + "opt-out-initiated");
        Put("optOutCancelled", Risc + "opt-out-cancelled");
        Put("optOutEffective", Risc + "opt-out-effective");
        Put("recoveryActivated", Risc + "recovery-activated");
        Put("recoveryInformationChanged", Risc + "recovery-information-changed");
        Put("sessionsRevoked", Risc + "sessions-revoked");
        Put("verification", Ssf + "verification");
        Put("streamUpdated", Ssf + "stream-updated");
        DefaultEventsRequested = new[]
        {
            Event["sessionRevoked"], Event["credentialChange"], Event["assuranceLevelChange"], Event["tokenClaimsChange"],
            Event["accountDisabled"], Event["accountEnabled"], Event["accountPurged"], Event["credentialCompromise"],
            Event["sessionsRevoked"], Event["accountCredentialChangeRequired"],
        };
        DefaultEndingEvents = new[]
        {
            Event["sessionRevoked"], Event["accountDisabled"], Event["accountPurged"],
            Event["credentialCompromise"], Event["sessionsRevoked"],
        };
    }

    static void Put(string name, string uri)
    {
        Event[name] = uri;
        if (uri.StartsWith(Caep, StringComparison.Ordinal)) CaepEvents.Add(uri);
        if (uri.StartsWith(Risc, StringComparison.Ordinal)) RiscEvents.Add(uri);
    }

    public static Dictionary<string, object?> SubjectOf(object? subId, string issuer)
    {
        var subject = Map(subId);
        if (subject == null) return new Dictionary<string, object?>();
        var format = Convert.ToString(Present(subject, "format", "subject_type")) ?? "";
        if (format == "complex" || (format.Length == 0 && (subject.GetValueOrDefault("user") != null || subject.GetValueOrDefault("session") != null)))
        {
            var user = Simple(subject.GetValueOrDefault("user"), issuer);
            var session = Simple(subject.GetValueOrDefault("session"), issuer);
            var output = new Dictionary<string, object?>();
            if (user.GetValueOrDefault("sub") is string person) output["person"] = person;
            if (user.GetValueOrDefault("email") is string email) output["email"] = email;
            var sessionId = session.GetValueOrDefault("opaque") ?? session.GetValueOrDefault("sub");
            if (sessionId is string id && id.Length > 0) output["idpSession"] = id;
            return output;
        }
        var one = Simple(subject, issuer);
        var flat = new Dictionary<string, object?>();
        if (one.GetValueOrDefault("sub") is string personOnly) flat["person"] = personOnly;
        if (one.GetValueOrDefault("email") is string emailOnly) flat["email"] = emailOnly;
        return flat;
    }

    static Dictionary<string, object?> Simple(object? identifier, string issuer)
    {
        var document = Map(identifier);
        if (document == null) return new Dictionary<string, object?>();
        var format = Convert.ToString(Present(document, "format", "subject_type")) ?? "";
        if (format == "iss_sub" && document.GetValueOrDefault("sub") is string sub && (document.GetValueOrDefault("iss") == null || issuer.Equals(document["iss"])))
        {
            return new Dictionary<string, object?> { ["sub"] = sub };
        }
        if (format == "email" && document.GetValueOrDefault("email") is string email) return new Dictionary<string, object?> { ["email"] = email };
        if (format == "opaque" && document.GetValueOrDefault("id") is string id) return new Dictionary<string, object?> { ["opaque"] = id };
        if (format == "aliases" && Jsons.List(document.GetValueOrDefault("identifiers")) is { } identifiers)
        {
            var merged = new Dictionary<string, object?>();
            foreach (var one in identifiers) foreach (var entry in Simple(one, issuer)) merged[entry.Key] = entry.Value;
            return merged;
        }
        return new Dictionary<string, object?>();
    }

    static object? Present(Dictionary<string, object?> document, params string[] names)
    {
        foreach (var name in names)
        {
            if (document.ContainsKey(name) && document[name] != null) return document[name];
        }
        return null;
    }

    static Dictionary<string, object?>? Map(object? value) => Jsons.Map(value);
}
