// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Text;
using System.Text.RegularExpressions;

namespace IyaSec.Oidc;

/// <summary>A Shared Signals receiver: one poll stream of CAEP and RISC events (RFC 8936).</summary>
public sealed class SignalsReceiver
{
    const string PollMethod = "urn:ietf:rfc:8936";
    static readonly Regex RefreshKeys = new("publishes no|does not verify", RegexOptions.Compiled);

    readonly string transmitter;
    readonly Action<IReadOnlyList<string>, Dictionary<string, object?>> onEnd;
    readonly Dictionary<string, string> tls;
    readonly Func<IReadOnlyDictionary<string, string>>? headers;
    readonly List<string> eventsRequested;
    readonly List<string> endOn;
    readonly string? description;
    readonly long pollIntervalMs;
    readonly int maxEvents;
    readonly Log log;
    readonly SessionIndex index;
    Dictionary<string, object?>? config;
    Dictionary<string, object?>? stream;
    List<Dictionary<string, object?>> keys = new();
    long keysAt;
    volatile bool running;
    readonly List<string> ack = new();
    readonly Dictionary<string, object?> errs = new();
    readonly Dictionary<string, List<Action<Dictionary<string, object?>>>> handlers = new();
    readonly object gate = new();
    readonly object wake = new();
    Task<bool>? inflight;
    Thread? loopThread;

    SignalsReceiver(Builder builder)
    {
        if (builder.OnEnd == null) throw new OidcError("config", "onEndSessions is required");
        if (string.IsNullOrEmpty(builder.Transmitter) || !Regex.IsMatch(builder.Transmitter, "^https?://.*"))
        {
            throw new OidcError("config", "transmitter must be an http(s) URL");
        }
        transmitter = builder.Transmitter.TrimEnd('/');
        onEnd = builder.OnEnd;
        tls = builder.Tls ?? new Dictionary<string, string>();
        headers = builder.Headers;
        eventsRequested = new List<string>(builder.EventsRequested ?? Events.DefaultEventsRequested);
        endOn = new List<string>(builder.EndOn ?? Events.DefaultEndingEvents);
        description = builder.Description;
        pollIntervalMs = builder.PollIntervalMs;
        maxEvents = builder.MaxEvents;
        log = builder.Logger ?? new PrintLog();
        index = builder.Index ?? new SessionIndex();
    }

    public static Builder New(string transmitter, Action<IReadOnlyList<string>, Dictionary<string, object?>> onEnd) => new(transmitter, onEnd);

    public Dictionary<string, object?>? Stream => stream;

    public void Track(IReadOnlyDictionary<string, object?> session) => index.Add(session);

    public void Untrack(string localId) => index.Remove(localId);

    public SignalsReceiver On(string eventType, Action<Dictionary<string, object?>> handler)
    {
        if (!handlers.TryGetValue(eventType, out var list))
        {
            list = new List<Action<Dictionary<string, object?>>>();
            handlers[eventType] = list;
        }
        list.Add(handler);
        return this;
    }

    public void Start()
    {
        if (running) return;
        config = Discover();
        Jwks(true);
        stream = EnsureStream();
        var delivery = Map(stream.GetValueOrDefault("delivery"));
        if (delivery == null || delivery.GetValueOrDefault("endpoint_url") is not string)
        {
            throw new OidcError("ssf", "the stream has no poll endpoint_url");
        }
        running = true;
        var delivered = Jsons.List(stream.GetValueOrDefault("events_delivered")) ?? new List<object?>();
        log.Info("ssf: polling stream " + stream.GetValueOrDefault("stream_id") + " at " + delivery["endpoint_url"] + ", delivering " + delivered.Count + " event type(s)");
        loopThread = new Thread(Loop) { IsBackground = true, Name = "ssf-poll" };
        loopThread.Start();
    }

    /// <summary>Stops polling and waits until the background poll has finished.</summary>
    public void Stop()
    {
        running = false;
        lock (wake) Monitor.PulseAll(wake);
        var thread = loopThread;
        if (thread != null && thread != Thread.CurrentThread)
        {
            thread.Join(TimeSpan.FromSeconds(20));
            if (loopThread == thread) loopThread = null;
        }
    }

    public bool PollOnce()
    {
        Task<bool> current;
        lock (gate)
        {
            if (inflight == null || inflight.IsCompleted)
            {
                inflight = Task.Run(PollNow);
            }
            current = inflight;
        }
        try
        {
            return current.GetAwaiter().GetResult();
        }
        catch (Exception err) when (err is not OidcError)
        {
            var cause = err is AggregateException aggregate && aggregate.InnerException != null ? aggregate.InnerException : err;
            if (cause is OidcError oidc) throw oidc;
            throw new OidcError("ssf", Convert.ToString(cause) ?? "", cause);
        }
    }

    void Loop()
    {
        while (running)
        {
            var delay = pollIntervalMs;
            try
            {
                if (PollOnce()) delay = 0;
            }
            catch (Exception err)
            {
                log.Warn("ssf: poll failed: " + err.Message);
                delay = Math.Min(pollIntervalMs * 4, 60_000);
            }
            if (!running) return;
            if (delay <= 0) continue;
            lock (wake)
            {
                if (running) Monitor.Wait(wake, TimeSpan.FromMilliseconds(delay));
            }
        }
    }

    bool PollNow()
    {
        var url = Convert.ToString(Map(stream!.GetValueOrDefault("delivery"))!["endpoint_url"])!;
        List<string> pendingAck;
        Dictionary<string, object?> pendingErrs;
        lock (ack)
        {
            pendingAck = new List<string>(ack);
            ack.Clear();
            pendingErrs = new Dictionary<string, object?>(errs);
            errs.Clear();
        }
        var body = new Dictionary<string, object?>
        {
            ["maxEvents"] = maxEvents,
            ["returnImmediately"] = true,
        };
        if (pendingAck.Count > 0) body["ack"] = pendingAck;
        if (pendingErrs.Count > 0) body["setErrs"] = pendingErrs;
        var answer = Call("POST", url, body);
        if (answer.Status != 200)
        {
            lock (ack)
            {
                var newer = new List<string>(pendingAck);
                newer.AddRange(ack);
                ack.Clear();
                ack.AddRange(newer);
                foreach (var entry in pendingErrs) errs.TryAdd(entry.Key, entry.Value);
            }
            throw new OidcError("ssf", "the poll answered " + answer.Status + ": " + Clip(answer.Json));
        }
        var payload = Map(answer.Json) ?? new Dictionary<string, object?>();
        var sets = Map(payload.GetValueOrDefault("sets")) ?? new Dictionary<string, object?>();
        foreach (var entry in sets)
        {
            var jti = entry.Key;
            try
            {
                Handle(jti, Convert.ToString(entry.Value) ?? "");
                lock (ack) ack.Add(jti);
            }
            catch (Exception err)
            {
                log.Warn("ssf: SET " + jti + " refused: " + err.Message);
                var code = err is OidcError oidc && oidc.Code == "signature" ? "invalid_key" : "invalid_request";
                var problem = new Dictionary<string, object?>
                {
                    ["err"] = code,
                    ["description"] = err.Message ?? Convert.ToString(err),
                };
                lock (ack) errs[jti] = problem;
            }
        }
        return payload.GetValueOrDefault("moreAvailable") is true;
    }

    void Handle(string jti, string token)
    {
        Dictionary<string, object?> verified;
        try
        {
            verified = SecEvent.VerifyCompactJws(token, Jwks(false));
        }
        catch (OidcError err)
        {
            if (err.Code != "signature" || err.Message == null || !RefreshKeys.IsMatch(err.Message)) throw;
            verified = SecEvent.VerifyCompactJws(token, Jwks(true));
        }
        var header = (Dictionary<string, object?>)verified["header"]!;
        var payload = (Dictionary<string, object?>)verified["payload"]!;
        if (header.GetValueOrDefault("typ") != null && !"secevent+jwt".Equals(Convert.ToString(header["typ"]), StringComparison.OrdinalIgnoreCase))
        {
            throw new OidcError("validation", "the SET's typ is " + header["typ"]);
        }
        if (!Equals(config!.GetValueOrDefault("issuer"), payload.GetValueOrDefault("iss")))
        {
            throw new OidcError("validation", "the SET was issued by " + payload.GetValueOrDefault("iss") + ", not " + config["issuer"]);
        }
        var want = Strings(stream!.GetValueOrDefault("aud"));
        var aud = Strings(payload.GetValueOrDefault("aud"));
        if (want.Count > 0 && !aud.Any(want.Contains))
        {
            throw new OidcError("validation", "the SET is for " + string.Join(", ", aud) + ", not this stream");
        }
        if (payload.GetValueOrDefault("jti") != null && jti != Convert.ToString(payload["jti"]))
        {
            throw new OidcError("validation", "the SET's jti is not the one it was delivered under");
        }
        var events = Map(payload.GetValueOrDefault("events"));
        if (events == null || events.Count == 0) throw new OidcError("validation", "the SET carries no events");
        foreach (var entry in events)
        {
            var eventType = entry.Key;
            var eventBody = Map(entry.Value);
            var subId = payload.GetValueOrDefault("sub_id") ?? eventBody?.GetValueOrDefault("subject");
            var subject = Events.SubjectOf(subId, Convert.ToString(config["issuer"])!);
            var sessions = SessionsFor(eventType, subject);
            var ends = endOn.Contains(eventType) && sessions.Count > 0;
            var signal = new Dictionary<string, object?>
            {
                ["type"] = eventType,
                ["payload"] = eventBody ?? new Dictionary<string, object?>(),
                ["subject"] = subject,
                ["jti"] = jti,
                ["sessions"] = sessions,
                ["ended"] = ends,
            };
            if (payload.GetValueOrDefault("iat") is byte or short or int or long or float or double or decimal) signal["iat"] = payload["iat"];
            if (payload.GetValueOrDefault("txn") is string txn) signal["txn"] = txn;
            if (ends)
            {
                try
                {
                    onEnd(sessions, signal);
                }
                catch (Exception err)
                {
                    log.Error("ssf: onEndSessions threw for " + eventType + " (SET " + jti + " is still acknowledged): " + err.Message);
                    signal["ended"] = false;
                    ends = false;
                }
                if (signal.GetValueOrDefault("ended") is true) foreach (var localId in sessions) index.Remove(localId);
            }
            var called = new List<Action<Dictionary<string, object?>>>();
            if (handlers.TryGetValue(eventType, out var typed)) called.AddRange(typed);
            if (handlers.TryGetValue("*", out var star)) called.AddRange(star);
            foreach (var handler in called)
            {
                try
                {
                    handler(signal);
                }
                catch (Exception err)
                {
                    log.Error("ssf: a handler for " + eventType + " threw (SET " + jti + " is still acknowledged): " + err.Message);
                }
            }
        }
    }

    List<string> SessionsFor(string eventType, Dictionary<string, object?> subject)
    {
        if (Events.Event["verification"] == eventType || Events.Event["streamUpdated"] == eventType) return new List<string>();
        if (subject.GetValueOrDefault("idpSession") is string idp)
        {
            var found = index.ByIdpSession(idp);
            if (found.Count > 0 || Events.Event["sessionRevoked"] == eventType) return found;
        }
        if (subject.GetValueOrDefault("person") is string person) return index.ByPerson(person);
        if (subject.GetValueOrDefault("email") is string email) return index.ByEmail(email);
        return new List<string>();
    }

    public void Verify(string? state)
    {
        var endpoint = config?.GetValueOrDefault("verification_endpoint");
        if (endpoint is not string url) throw new OidcError("ssf", "the transmitter publishes no verification_endpoint");
        var body = new Dictionary<string, object?> { ["stream_id"] = stream!.GetValueOrDefault("stream_id") };
        if (!string.IsNullOrEmpty(state)) body["state"] = state;
        var answer = Call("POST", url, body);
        if (answer.Status != 200 && answer.Status != 204) throw new OidcError("ssf", "verification answered " + answer.Status);
    }

    Dictionary<string, object?> Discover()
    {
        var urls = Discovery.WellKnownUrls(transmitter, "ssf-configuration");
        var last = new OidcError("ssf", "no transmitter configuration at " + string.Join(" or ", urls));
        for (var i = 0; i < urls.Count; i++)
        {
            var url = urls[i];
            var answer = Call("GET", url, null);
            var doc = Map(answer.Json);
            if (answer.Status == 404 && i < urls.Count - 1) continue;
            if (answer.Status != 200 || doc == null || !Text(doc.GetValueOrDefault("configuration_endpoint")) || !Text(doc.GetValueOrDefault("jwks_uri")))
            {
                last = new OidcError("ssf", url + " answered " + answer.Status + " without a usable transmitter configuration");
                continue;
            }
            if (Jsons.List(doc.GetValueOrDefault("delivery_methods_supported")) is { } methods && methods.Count > 0 && !methods.Contains(PollMethod))
            {
                throw new OidcError("ssf", "the transmitter does not offer poll delivery (RFC 8936)");
            }
            return doc;
        }
        throw last;
    }

    List<Dictionary<string, object?>> Jwks(bool force)
    {
        if (!force && keys.Count > 0 && (DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0) - keysAt < 3600) return keys;
        var answer = Call("GET", Convert.ToString(config!.GetValueOrDefault("jwks_uri"))!, null);
        var raw = Map(answer.Json) == null ? null : Jsons.List(Map(answer.Json)!.GetValueOrDefault("keys"));
        if (answer.Status != 200 || raw == null) throw new OidcError("ssf", "the transmitter's JWKS answered " + answer.Status);
        var parsed = new List<Dictionary<string, object?>>();
        foreach (var item in raw)
        {
            var jwk = Map(item);
            if (jwk != null) parsed.Add(jwk);
        }
        keys = parsed;
        keysAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        return keys;
    }

    Dictionary<string, object?> EnsureStream()
    {
        var endpoint = Convert.ToString(config!.GetValueOrDefault("configuration_endpoint"))!;
        var listed = Call("GET", endpoint, null);
        if (listed.Status == 200)
        {
            var all = Jsons.List(listed.Json) ?? (listed.Json == null ? new List<object?>() : new List<object?> { listed.Json });
            foreach (var item in all)
            {
                var candidate = Map(item);
                var delivery = candidate == null ? null : Map(candidate.GetValueOrDefault("delivery"));
                if (candidate != null && delivery != null && PollMethod.Equals(delivery.GetValueOrDefault("method")) && Text(candidate.GetValueOrDefault("stream_id")))
                {
                    return candidate;
                }
            }
        }
        else if (listed.Status != 404)
        {
            throw new OidcError("ssf", "listing the streams at " + endpoint + " answered " + listed.Status + ": " + Clip(listed.Json));
        }
        var body = new Dictionary<string, object?>
        {
            ["delivery"] = new Dictionary<string, object?> { ["method"] = PollMethod },
            ["events_requested"] = eventsRequested,
        };
        if (!string.IsNullOrEmpty(description)) body["description"] = description;
        var created = Call("POST", endpoint, body);
        var made = Map(created.Json);
        if ((created.Status != 200 && created.Status != 201) || made == null || !Text(made.GetValueOrDefault("stream_id")))
        {
            throw new OidcError("ssf", "creating a stream at " + endpoint + " answered " + created.Status + ": " + Clip(created.Json));
        }
        return made;
    }

    Answer Call(string method, string url, object? body)
    {
        var requestHeaders = new Dictionary<string, string> { ["accept"] = "application/json" };
        if (headers != null)
        {
            foreach (var entry in headers()) requestHeaders[entry.Key] = entry.Value;
        }
        byte[]? payload = null;
        if (body != null)
        {
            requestHeaders["content-type"] = "application/json";
            payload = Encoding.UTF8.GetBytes(Jsons.Write(body));
        }
        var answer = Http.Send(url, method, requestHeaders, payload, tls, "ssf");
        object? parsed = null;
        if (!string.IsNullOrEmpty(answer.Body))
        {
            try
            {
                parsed = Jsons.Read(answer.Body);
            }
            catch (ArgumentException)
            {
                parsed = answer.Body;
            }
        }
        return new Answer(answer.Status, parsed);
    }

    static string Clip(object? value)
    {
        string text;
        try
        {
            text = Jsons.Write(value);
        }
        catch (Exception)
        {
            text = Convert.ToString(value) ?? "";
        }
        return text.Length > 300 ? text[..300] : text;
    }

    static Dictionary<string, object?>? Map(object? value) => Jsons.Map(value);

    static List<string> Strings(object? value)
    {
        if (Jsons.List(value) is { } items) return items.Select(item => Convert.ToString(item) ?? "").ToList();
        if (value == null) return new List<string>();
        return new List<string> { Convert.ToString(value)! };
    }

    static bool Text(object? value) => value is string text && text.Length > 0;

    readonly record struct Answer(int Status, object? Json);

    public interface Log
    {
        void Info(string message);
        void Warn(string message);
        void Error(string message);
    }

    sealed class PrintLog : Log
    {
        public void Info(string message) => Console.WriteLine(message);
        public void Warn(string message) => Console.WriteLine(message);
        public void Error(string message) => Console.WriteLine(message);
    }

    public sealed class Builder
    {
        internal string Transmitter { get; }
        internal Action<IReadOnlyList<string>, Dictionary<string, object?>>? OnEnd { get; }
        internal Dictionary<string, string>? Tls { get; private set; }
        internal Func<IReadOnlyDictionary<string, string>>? Headers { get; private set; }
        internal IReadOnlyList<string>? EventsRequested { get; private set; }
        internal IReadOnlyList<string>? EndOn { get; private set; }
        internal SessionIndex? Index { get; private set; }
        internal string? Description { get; private set; }
        internal long PollIntervalMs { get; private set; } = 5000;
        internal int MaxEvents { get; private set; } = 50;
        internal Log? Logger { get; private set; }

        internal Builder(string transmitter, Action<IReadOnlyList<string>, Dictionary<string, object?>> onEnd)
        {
            Transmitter = transmitter;
            OnEnd = onEnd;
        }

        public Builder WithTls(Dictionary<string, string> value) { Tls = value; return this; }
        public Builder WithHeaders(Func<IReadOnlyDictionary<string, string>> value) { Headers = value; return this; }
        public Builder WithEventsRequested(IReadOnlyList<string> value) { EventsRequested = value; return this; }
        public Builder WithEndOn(IReadOnlyList<string> value) { EndOn = value; return this; }
        public Builder WithSessionIndex(SessionIndex value) { Index = value; return this; }
        public Builder WithDescription(string value) { Description = value; return this; }
        public Builder WithPollIntervalMs(long value) { PollIntervalMs = value <= 0 ? 5000 : value; return this; }
        public Builder WithMaxEvents(int value) { MaxEvents = value <= 0 ? 50 : value; return this; }
        public Builder WithLog(Log value) { Logger = value; return this; }
        public SignalsReceiver Build() => new(this);
    }
}
