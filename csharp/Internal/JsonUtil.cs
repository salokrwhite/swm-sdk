using System.Text;
using System.Text.Json;

namespace SwmSdk.Internal;

internal static class JsonUtil
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    public static byte[] SerializeToUtf8<T>(T value)
    {
        return JsonSerializer.SerializeToUtf8Bytes(value, Options);
    }

    public static T Deserialize<T>(ReadOnlySpan<byte> utf8)
    {
        return JsonSerializer.Deserialize<T>(utf8, Options)
            ?? throw new SwmProtocolException("empty JSON response");
    }

    public static string ToJsonString(object? value)
    {
        return JsonSerializer.Serialize(value, Options);
    }

    public static JsonElement ToJsonElement(object? value)
    {
        using var document = JsonDocument.Parse(ToJsonString(value));
        return document.RootElement.Clone();
    }

    public static Dictionary<string, JsonElement> ToElementMap(IDictionary<string, object?>? values)
    {
        var result = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        if (values == null)
        {
            return result;
        }
        foreach (var pair in values)
        {
            result[pair.Key] = ToJsonElement(pair.Value);
        }
        return result;
    }

    public static Dictionary<string, JsonElement> ToElementMap(IReadOnlyDictionary<string, object?>? values)
    {
        var result = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        if (values == null)
        {
            return result;
        }
        foreach (var pair in values)
        {
            result[pair.Key] = ToJsonElement(pair.Value);
        }
        return result;
    }

    public static bool TryGetRawData(ReadOnlySpan<byte> utf8, out byte[] data, out string? authzRaw)
    {
        data = Array.Empty<byte>();
        authzRaw = null;
        using var document = JsonDocument.Parse(utf8.ToArray());
        if (!document.RootElement.TryGetProperty("data", out var dataElement) ||
            !document.RootElement.TryGetProperty("authz", out var authzElement))
        {
            return false;
        }
        data = Encoding.UTF8.GetBytes(dataElement.GetRawText());
        authzRaw = authzElement.GetRawText();
        return true;
    }
}
