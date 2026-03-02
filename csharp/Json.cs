using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace SwmSdk;

internal static class JsonDefaults
{
    public static JsonSerializerOptions Options => SwmJsonContext.Default.Options;

    public static StringContent ToJsonContent<T>(T payload, JsonTypeInfo<T> typeInfo)
    {
        var json = JsonSerializer.Serialize(payload, typeInfo);
        return new StringContent(json, Encoding.UTF8, "application/json");
    }

    public static async Task<T> DeserializeAsync<T>(HttpContent content, JsonTypeInfo<T> typeInfo, CancellationToken cancellationToken = default)
    {
        using var stream = await content.ReadAsStreamAsync().ConfigureAwait(false);
        var value = await JsonSerializer.DeserializeAsync(stream, typeInfo, cancellationToken).ConfigureAwait(false);
        if (value == null)
        {
            throw new SwmApiException(0, null, "empty response body");
        }
        return (T)value;
    }

    public static Dictionary<string, JsonElement> ToJsonElementMap(Dictionary<string, object?> source)
    {
        var result = new Dictionary<string, JsonElement>(source.Count);
        foreach (var kv in source)
        {
            result[kv.Key] = ToJsonElement(kv.Value);
        }
        return result;
    }

    public static JsonElement ToJsonElement(object? value)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            WriteDynamicValue(writer, value);
        }
        var doc = JsonDocument.Parse(stream.ToArray());
        return doc.RootElement.Clone();
    }

    private static void WriteDynamicValue(Utf8JsonWriter writer, object? value)
    {
        if (value == null)
        {
            writer.WriteNullValue();
            return;
        }
        switch (value)
        {
            case JsonElement elem:
                elem.WriteTo(writer);
                return;
            case string s:
                writer.WriteStringValue(s);
                return;
            case bool b:
                writer.WriteBooleanValue(b);
                return;
            case int i:
                writer.WriteNumberValue(i);
                return;
            case long l:
                writer.WriteNumberValue(l);
                return;
            case float f:
                writer.WriteNumberValue(f);
                return;
            case double d:
                writer.WriteNumberValue(d);
                return;
            case decimal m:
                writer.WriteNumberValue(m);
                return;
            case short sh:
                writer.WriteNumberValue(sh);
                return;
            case byte bt:
                writer.WriteNumberValue(bt);
                return;
            case uint ui:
                writer.WriteNumberValue(ui);
                return;
            case ulong ul:
                writer.WriteNumberValue(ul);
                return;
            case DateTime dt:
                writer.WriteStringValue(dt);
                return;
            case Guid g:
                writer.WriteStringValue(g);
                return;
            case IDictionary<string, JsonElement> jsonMap:
                writer.WriteStartObject();
                foreach (var kv in jsonMap)
                {
                    writer.WritePropertyName(kv.Key);
                    kv.Value.WriteTo(writer);
                }
                writer.WriteEndObject();
                return;
            case IDictionary<string, object?> objMap:
                writer.WriteStartObject();
                foreach (var kv in objMap)
                {
                    writer.WritePropertyName(kv.Key);
                    WriteDynamicValue(writer, kv.Value);
                }
                writer.WriteEndObject();
                return;
            case IEnumerable<object?> seq:
                writer.WriteStartArray();
                foreach (var item in seq)
                {
                    WriteDynamicValue(writer, item);
                }
                writer.WriteEndArray();
                return;
            case System.Collections.IEnumerable nonGeneric when value is not string:
                writer.WriteStartArray();
                foreach (var item in nonGeneric)
                {
                    WriteDynamicValue(writer, item);
                }
                writer.WriteEndArray();
                return;
            default:
                writer.WriteStringValue(value.ToString());
                return;
        }
    }
}
