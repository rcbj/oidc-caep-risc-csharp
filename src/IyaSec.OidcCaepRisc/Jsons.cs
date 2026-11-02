// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Text;
using System.Text.Json;

namespace IyaSec.Oidc;

/// <summary>JSON objects keep the order they were written in.</summary>
public static class Jsons
{
    public static object? Read(string text)
    {
        try
        {
            using var doc = JsonDocument.Parse(text);
            return FromElement(doc.RootElement);
        }
        catch (Exception err)
        {
            throw new ArgumentException(err.Message, err);
        }
    }

    public static string Write(object? value)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            WriteValue(writer, value);
        }
        return Encoding.UTF8.GetString(stream.ToArray());
    }

    public static Dictionary<string, object?>? Map(object? value)
    {
        if (value is Dictionary<string, object?> typed)
        {
            return new Dictionary<string, object?>(typed);
        }
        if (value is IDictionary<string, object?> generic)
        {
            return new Dictionary<string, object?>(generic);
        }
        if (value is System.Collections.IDictionary raw)
        {
            var copy = new Dictionary<string, object?>();
            foreach (System.Collections.DictionaryEntry entry in raw)
            {
                copy[Convert.ToString(entry.Key) ?? ""] = entry.Value;
            }
            return copy;
        }
        return null;
    }

    public static List<object?>? List(object? value)
    {
        if (value is List<object?> typed) return typed;
        if (value is System.Collections.IList raw && value is not string)
        {
            var copy = new List<object?>();
            foreach (var item in raw) copy.Add(item);
            return copy;
        }
        return null;
    }

    static object? FromElement(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                var map = new Dictionary<string, object?>();
                foreach (var property in element.EnumerateObject()) map[property.Name] = FromElement(property.Value);
                return map;
            case JsonValueKind.Array:
                var list = new List<object?>();
                foreach (var item in element.EnumerateArray()) list.Add(FromElement(item));
                return list;
            case JsonValueKind.String:
                return element.GetString();
            case JsonValueKind.True:
                return true;
            case JsonValueKind.False:
                return false;
            case JsonValueKind.Null:
                return null;
            case JsonValueKind.Number:
                if (element.TryGetInt64(out var whole)) return whole;
                return element.GetDouble();
            default:
                return null;
        }
    }

    static void WriteValue(Utf8JsonWriter writer, object? value)
    {
        switch (value)
        {
            case null:
                writer.WriteNullValue();
                return;
            case bool bit:
                writer.WriteBooleanValue(bit);
                return;
            case string text:
                writer.WriteStringValue(text);
                return;
            case byte number:
                writer.WriteNumberValue(number);
                return;
            case short number:
                writer.WriteNumberValue(number);
                return;
            case int number:
                writer.WriteNumberValue(number);
                return;
            case long number:
                writer.WriteNumberValue(number);
                return;
            case float number:
                writer.WriteNumberValue(number);
                return;
            case double number:
                writer.WriteNumberValue(number);
                return;
            case decimal number:
                writer.WriteNumberValue(number);
                return;
            case JsonElement element:
                element.WriteTo(writer);
                return;
        }
        var mapped = Map(value);
        if (mapped != null && value is not string)
        {
            writer.WriteStartObject();
            foreach (var entry in mapped)
            {
                writer.WritePropertyName(entry.Key);
                WriteValue(writer, entry.Value);
            }
            writer.WriteEndObject();
            return;
        }
        var listed = List(value);
        if (listed != null)
        {
            writer.WriteStartArray();
            foreach (var item in listed) WriteValue(writer, item);
            writer.WriteEndArray();
            return;
        }
        writer.WriteStringValue(Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture));
    }
}
