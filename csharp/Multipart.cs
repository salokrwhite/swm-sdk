using System.Net.Http.Headers;

namespace SwmSdk;

internal static class MultipartBuilder
{
    public static async Task<(MultipartFormDataContent Form, List<Stream> Streams)> BuildFeedbackFormAsync(
        Client client,
        string content,
        int? rating,
        string? contact,
        IEnumerable<string>? attachments,
        Dictionary<string, object?>? metadata)
    {
        var form = new MultipartFormDataContent();
        var streams = new List<Stream>();

        form.Add(new StringContent(client.DeviceId), "device_id");
        if (!string.IsNullOrWhiteSpace(client.Channel))
        {
            form.Add(new StringContent(client.Channel), "channel_code");
        }
        form.Add(new StringContent(content), "content");
        if (rating.HasValue)
        {
            form.Add(new StringContent(rating.Value.ToString()), "rating");
        }
        if (!string.IsNullOrWhiteSpace(contact))
        {
            form.Add(new StringContent(contact), "contact");
        }

        var merged = metadata != null
            ? new Dictionary<string, object?>(metadata)
            : new Dictionary<string, object?>();

        if (client.Attributes.Count > 0 && !merged.ContainsKey("attributes"))
        {
            merged["attributes"] = client.Attributes;
        }
        if (merged.Count > 0)
        {
            var jsonMetadata = JsonDefaults.ToJsonElementMap(merged);
            form.Add(JsonDefaults.ToJsonContent(jsonMetadata, SwmJsonContext.Default.DictionaryStringJsonElement), "metadata");
            if (merged.TryGetValue("app_version", out var appVersion) && appVersion != null)
            {
                form.Add(new StringContent(appVersion.ToString() ?? string.Empty), "app_version");
            }
        }

        if (attachments != null)
        {
            foreach (var filePath in attachments)
            {
                if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
                {
                    continue;
                }
                var stream = File.OpenRead(filePath);
                streams.Add(stream);
                var fileContent = new StreamContent(stream);
                fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
                form.Add(fileContent, "attachments", Path.GetFileName(filePath));
            }
        }

        await Task.CompletedTask.ConfigureAwait(false);
        return (form, streams);
    }
}
