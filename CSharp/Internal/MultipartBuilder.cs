using System.Text;
using System.Text.Json;

namespace SwmSdk.Internal;

internal sealed record MultipartPayload(byte[] Body, string ContentType);

internal static class MultipartBuilder
{
    private const int MaximumPayloadBytes = 32 * 1024 * 1024;
    private const int MaximumAttachments = 3;
    private const long MaximumAttachmentBytes = 5L * 1024 * 1024;

    public static async Task<MultipartPayload> BuildFeedbackAsync(
        string deviceId,
        string channel,
        string defaultAppVersion,
        FeedbackRequest request,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.Content))
        {
            throw new SwmValidationException(0, null, "feedback content is required");
        }
        if (request.Rating is < 1 or > 5)
        {
            throw new SwmValidationException(0, null, "feedback rating must be between 1 and 5");
        }

        var boundary = "----------------------------" +
            Convert.ToHexString(CryptoUtil.RandomBytes(12)).ToLowerInvariant();
        await using var stream = new MemoryStream();
        await WriteFieldAsync(stream, boundary, "device_id", deviceId, cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(channel))
        {
            await WriteFieldAsync(stream, boundary, "channel_code", channel, cancellationToken).ConfigureAwait(false);
        }
        await WriteFieldAsync(stream, boundary, "content", request.Content, cancellationToken).ConfigureAwait(false);
        if (request.Rating.HasValue)
        {
            await WriteFieldAsync(
                stream,
                boundary,
                "rating",
                request.Rating.Value.ToString(System.Globalization.CultureInfo.InvariantCulture),
                cancellationToken).ConfigureAwait(false);
        }
        if (!string.IsNullOrWhiteSpace(request.Contact))
        {
            await WriteFieldAsync(stream, boundary, "contact", request.Contact, cancellationToken).ConfigureAwait(false);
        }
        var appVersion = string.IsNullOrWhiteSpace(request.AppVersion)
            ? defaultAppVersion
            : request.AppVersion;
        if (!string.IsNullOrWhiteSpace(appVersion))
        {
            await WriteFieldAsync(stream, boundary, "app_version", appVersion, cancellationToken).ConfigureAwait(false);
        }
        if (request.Metadata is { Count: > 0 })
        {
            var metadata = JsonUtil.ToJsonString(request.Metadata);
            await WriteFieldAsync(stream, boundary, "metadata", metadata, cancellationToken).ConfigureAwait(false);
        }

        var attachmentPaths = request.AttachmentPaths
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .ToArray();
        if (attachmentPaths.Length > MaximumAttachments)
        {
            throw new SwmValidationException(0, null, "feedback supports at most 3 attachments");
        }
        foreach (var path in attachmentPaths)
        {
            if (!File.Exists(path))
            {
                throw new SwmValidationException(0, null, $"feedback attachment was not found: {path}");
            }
            var info = new FileInfo(path);
            if (info.Length > MaximumAttachmentBytes)
            {
                throw new SwmValidationException(0, null, $"feedback attachment exceeds 5 MiB: {path}");
            }
            if (stream.Length + info.Length > MaximumPayloadBytes)
            {
                throw new SwmValidationException(0, null, "feedback payload exceeds 32 MiB");
            }
            await WriteFileAsync(stream, boundary, path, cancellationToken).ConfigureAwait(false);
        }

        await WriteAsciiAsync(stream, $"--{boundary}--\r\n", cancellationToken).ConfigureAwait(false);
        if (stream.Length > MaximumPayloadBytes)
        {
            throw new SwmValidationException(0, null, "feedback payload exceeds 32 MiB");
        }
        return new MultipartPayload(stream.ToArray(), $"multipart/form-data; boundary={boundary}");
    }

    private static async Task WriteFieldAsync(
        Stream stream,
        string boundary,
        string name,
        string value,
        CancellationToken cancellationToken)
    {
        await WriteAsciiAsync(stream, $"--{boundary}\r\n", cancellationToken).ConfigureAwait(false);
        await WriteAsciiAsync(
            stream,
            $"Content-Disposition: form-data; name=\"{Escape(name)}\"\r\n\r\n",
            cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(Encoding.UTF8.GetBytes(value), cancellationToken).ConfigureAwait(false);
        await WriteAsciiAsync(stream, "\r\n", cancellationToken).ConfigureAwait(false);
    }

    private static async Task WriteFileAsync(
        Stream stream,
        string boundary,
        string path,
        CancellationToken cancellationToken)
    {
        await WriteAsciiAsync(stream, $"--{boundary}\r\n", cancellationToken).ConfigureAwait(false);
        await WriteAsciiAsync(
            stream,
            $"Content-Disposition: form-data; name=\"attachments\"; filename=\"{Escape(Path.GetFileName(path))}\"\r\n",
            cancellationToken).ConfigureAwait(false);
        await WriteAsciiAsync(stream, "Content-Type: application/octet-stream\r\n\r\n", cancellationToken)
            .ConfigureAwait(false);
        await using var source = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            128 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        await source.CopyToAsync(stream, cancellationToken).ConfigureAwait(false);
        await WriteAsciiAsync(stream, "\r\n", cancellationToken).ConfigureAwait(false);
    }

    private static Task WriteAsciiAsync(Stream stream, string value, CancellationToken cancellationToken)
    {
        return stream.WriteAsync(Encoding.ASCII.GetBytes(value), cancellationToken).AsTask();
    }

    private static string Escape(string value)
    {
        return value.Replace("\"", "%22").Replace("\r", string.Empty).Replace("\n", string.Empty);
    }
}
