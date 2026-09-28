using System.Net;
using System.Security.Cryptography;
using SwmSdk.Internal;

namespace SwmSdk;

public sealed partial class SwmClient
{
    public async Task DownloadUpdateAsync(
        UpdateCheckResponse update,
        string destinationPath,
        Action<long, long>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(update);
        if (!update.UpdateAvailable || update.OpenInBrowser)
        {
            throw new SwmValidationException(0, null, "update does not contain a downloadable package");
        }
        if (string.IsNullOrWhiteSpace(destinationPath))
        {
            throw new SwmValidationException(0, null, "destinationPath is required");
        }
        var url = ValidateDownloadUrl(update.DownloadUrl);
        var fullDestination = Path.GetFullPath(destinationPath);
        var directory = Path.GetDirectoryName(fullDestination);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }
        var partial = fullDestination + ".part";
        var policy = RequestPolicies.Resolve(SwmOperationClass.Download);
        Exception? lastError = null;
        for (var attempt = 0; attempt <= policy.Retries; attempt++)
        {
            try
            {
                await DownloadRangeAsync(url, partial, progress, cancellationToken).ConfigureAwait(false);
                lastError = null;
                break;
            }
            catch (Exception ex) when (ex is HttpRequestException or IOException or SwmTimeoutException)
            {
                lastError = ex;
                if (attempt >= policy.Retries)
                {
                    break;
                }
                await Task.Delay(BackoffDelay(policy, attempt), cancellationToken).ConfigureAwait(false);
            }
        }
        if (lastError != null)
        {
            throw lastError;
        }

        byte[] hash;
        await using (var stream = new FileStream(
                         partial,
                         FileMode.Open,
                         FileAccess.Read,
                         FileShare.Read,
                         128 * 1024,
                         FileOptions.Asynchronous | FileOptions.SequentialScan))
        {
            hash = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        }
        var actualHash = Convert.ToHexString(hash).ToLowerInvariant();
        try
        {
            ArtifactVerifier.VerifyDownload(update, actualHash);
        }
        catch
        {
            File.Delete(partial);
            throw;
        }
        File.Move(partial, fullDestination, true);
    }

    private async Task DownloadRangeAsync(
        Uri url,
        string partialPath,
        Action<long, long>? progress,
        CancellationToken cancellationToken)
    {
        var existingLength = File.Exists(partialPath) ? new FileInfo(partialPath).Length : 0;
        using var initialResponse = await _pipeline.SendDownloadAsync(
            url,
            existingLength,
            cancellationToken).ConfigureAwait(false);
        HttpResponseMessage response;
        if ((int)initialResponse.StatusCode is >= 300 and < 400)
        {
            var location = initialResponse.Headers.Location;
            if (location == null)
            {
                throw new SwmProtocolException("artifact download redirect is missing a location");
            }
            var storageUrl = location.IsAbsoluteUri ? location : new Uri(url, location);
            response = await _pipeline.SendStorageRequestAsync(
                storageUrl,
                existingLength > 0 ? existingLength : null,
                cancellationToken).ConfigureAwait(false);
        }
        else
        {
            response = initialResponse;
        }
        using (response)
        {
            if ((int)response.StatusCode >= 400)
            {
                var body = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
                _pipeline.ThrowIfError(new ProtocolResponse(
                    (int)response.StatusCode,
                    body,
                    string.Empty,
                    response.Headers.ToDictionary(
                        pair => pair.Key,
                        pair => pair.Value.ToArray(),
                        StringComparer.OrdinalIgnoreCase)));
            }
            var append = existingLength > 0 && response.StatusCode == HttpStatusCode.PartialContent;
            if (!append)
            {
                existingLength = 0;
            }
            var expectedTotal = response.Content.Headers.ContentRange?.Length ??
                (response.Content.Headers.ContentLength.HasValue
                    ? existingLength + response.Content.Headers.ContentLength.Value
                    : 0);
            await using var source = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            await using var target = new FileStream(
                partialPath,
                append ? FileMode.Append : FileMode.Create,
                FileAccess.Write,
                FileShare.None,
                128 * 1024,
                FileOptions.Asynchronous);
            var buffer = new byte[128 * 1024];
            var written = existingLength;
            progress?.Invoke(written, expectedTotal);
            while (true)
            {
                var read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }
                await target.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                written += read;
                progress?.Invoke(written, expectedTotal);
            }
            await target.FlushAsync(cancellationToken).ConfigureAwait(false);
            if (expectedTotal > 0 && written != expectedTotal)
            {
                throw new IOException($"download length mismatch: {written} != {expectedTotal}");
            }
        }
    }

    private Uri ValidateDownloadUrl(string? rawUrl)
    {
        if (!Uri.TryCreate(rawUrl, UriKind.Absolute, out var uri) ||
            uri.Scheme != _options.BaseUri.Scheme ||
            !string.Equals(uri.Host, _options.BaseUri.Host, StringComparison.OrdinalIgnoreCase) ||
            uri.Port != _options.BaseUri.Port)
        {
            throw new SwmIntegrityException(
                0,
                "download_url_invalid",
                "download URL is not bound to the configured SWM origin",
                _pipeline.LastFailureAction);
        }
        var segments = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length != 5 ||
            segments[0] != "api" || segments[1] != "client" ||
            segments[2] != "artifacts" || segments[4] != "download" ||
            !Guid.TryParse(segments[3], out _) ||
            !uri.Query.Contains("ticket=", StringComparison.Ordinal))
        {
            throw new SwmIntegrityException(
                0,
                "download_url_invalid",
                "download URL does not match the fixed artifact ticket route",
                _pipeline.LastFailureAction);
        }
        return uri;
    }

    private static TimeSpan BackoffDelay(RequestPolicy policy, int attempt)
    {
        var scaled = (long)policy.BackoffMilliseconds << Math.Min(attempt, 16);
        return TimeSpan.FromMilliseconds(Math.Min(
            scaled,
            Math.Max(policy.BackoffMaxMilliseconds, policy.BackoffMilliseconds)));
    }
}
