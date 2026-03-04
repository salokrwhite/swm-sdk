using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace SwmSdk;

public partial class Client
{
    public const string ControlEventShutdown = "device_shutdown";
    public const string ApiErrorCodeDeviceBlocked = "device_blocked";
    public const string ApiErrorCodeUpdateRegionBlocked = "update_region_blocked";

    public string BaseUrl { get; }
    public string AppId { get; }
    public string AppSecret { get; }
    public string AuthToken { get; private set; } = string.Empty;
    public string Channel { get; set; } = string.Empty;
    public string Platform { get; set; } = string.Empty;
    public string Arch { get; set; } = string.Empty;
    public string DeviceId { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public Dictionary<string, object?> Attributes { get; set; } = new();
    public string? PublicKey { get; set; }
    public bool VerifySignature { get; set; }
    public Func<string, string, bool>? SignatureVerifier { get; set; }
    public int Retries { get; set; } = 2;
    public TimeSpan Backoff { get; set; } = TimeSpan.FromMilliseconds(500);
    public HttpClient HttpClient { get; }
    internal static readonly HttpMethod PatchMethod = new("PATCH");

    public Client(string baseUrl, string appId, string appSecret, HttpClient? httpClient = null)
    {
        BaseUrl = baseUrl.TrimEnd('/');
        AppId = appId;
        AppSecret = appSecret;
        HttpClient = httpClient ?? new HttpClient();
    }

    public void SetAuthToken(string token)
    {
        AuthToken = token?.Trim() ?? string.Empty;
    }

    private static string HexLower(byte[] bytes)
    {
        var sb = new StringBuilder(bytes.Length * 2);
        for (var i = 0; i < bytes.Length; i++)
        {
            sb.Append(bytes[i].ToString("x2"));
        }
        return sb.ToString();
    }

    private static byte[] DecodeBase64OrHex(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            throw new SwmApiException(0, null, "empty key");
        }
        try
        {
            return Convert.FromBase64String(input);
        }
        catch
        {
            // ignore
        }

        if (input.Length % 2 != 0)
        {
            throw new SwmApiException(0, null, "invalid key encoding");
        }

        var bytes = new byte[input.Length / 2];
        for (var i = 0; i < input.Length; i += 2)
        {
            bytes[i / 2] = Convert.ToByte(input.Substring(i, 2), 16);
        }
        return bytes;
    }

    private bool VerifySignatureInternal(string checksumHex, string signature)
    {
        if (!VerifySignature)
        {
            return true;
        }

        if (SignatureVerifier != null)
        {
            return SignatureVerifier(checksumHex, signature);
        }

        if (string.IsNullOrWhiteSpace(PublicKey))
        {
            return true;
        }

        var publicKeyBytes = DecodeBase64OrHex(PublicKey!);
        var signatureBytes = DecodeBase64OrHex(signature);
        var messageBytes = Encoding.UTF8.GetBytes(checksumHex);

        try
        {
            var verifier = new Ed25519Signer();
            verifier.Init(false, new Ed25519PublicKeyParameters(publicKeyBytes, 0));
            verifier.BlockUpdate(messageBytes, 0, messageBytes.Length);
            return verifier.VerifySignature(signatureBytes);
        }
        catch (Exception ex) when (ex is ArgumentException || ex is InvalidOperationException)
        {
            throw new SwmApiException(0, null, $"invalid ed25519 verification parameters: {ex.Message}");
        }
    }

    private async Task<HttpResponseMessage> DoRequestAsync(HttpMethod method, string path, HttpContent? body = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(AppId) || string.IsNullOrWhiteSpace(AppSecret))
        {
            throw new SwmValidationException(400, null, "app_id and app_secret required");
        }

        var bodyBytes = body != null ? await body.ReadAsByteArrayAsync().ConfigureAwait(false) : Array.Empty<byte>();
        Exception? last = null;
        for (var attempt = 0; attempt <= Retries; attempt++)
        {
            try
            {
                using var req = new HttpRequestMessage(method, $"{BaseUrl}{path}");
                if (body != null)
                {
                    var clone = new ByteArrayContent(bodyBytes);
                    foreach (var header in body.Headers)
                    {
                        clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
                    }
                    req.Content = clone;
                }
                SignClientRequest(req, bodyBytes);
                var resp = await HttpClient.SendAsync(req, cancellationToken).ConfigureAwait(false);
                return resp;
            }
            catch (Exception ex)
            {
                last = ex;
                var delay = TimeSpan.FromMilliseconds(Backoff.TotalMilliseconds * Math.Pow(2, attempt));
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            }
        }
        throw last ?? new SwmApiException(0, null, "request failed");
    }

    private async Task<HttpResponseMessage> DoAuthRequestAsync(HttpMethod method, string path, Dictionary<string, string?>? query = null, HttpContent? body = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(AuthToken))
        {
            throw new SwmUnauthorizedException(401, null, "auth token required, call SetAuthToken first");
        }

        var fullPath = $"{BaseUrl}{path}";
        if (query != null && query.Count > 0)
        {
            var q = string.Join("&", query.Where(kv => !string.IsNullOrWhiteSpace(kv.Value))
                .Select(kv => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value!)}"));
            if (!string.IsNullOrWhiteSpace(q))
            {
                fullPath += "?" + q;
            }
        }

        var bodyBytes = body != null ? await body.ReadAsByteArrayAsync().ConfigureAwait(false) : Array.Empty<byte>();
        Exception? last = null;
        for (var attempt = 0; attempt <= Retries; attempt++)
        {
            try
            {
                using var req = new HttpRequestMessage(method, fullPath);
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", AuthToken);
                if (body != null)
                {
                    var clone = new ByteArrayContent(bodyBytes);
                    foreach (var header in body.Headers)
                    {
                        clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
                    }
                    req.Content = clone;
                }
                SignAuthRequest(req, bodyBytes, AuthToken);
                var resp = await HttpClient.SendAsync(req, cancellationToken).ConfigureAwait(false);
                return resp;
            }
            catch (Exception ex)
            {
                last = ex;
                var delay = TimeSpan.FromMilliseconds(Backoff.TotalMilliseconds * Math.Pow(2, attempt));
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            }
        }
        throw last ?? new SwmApiException(0, null, "request failed");
    }

    public async Task<UpdateCheckResponse> CheckUpdateAsync(string currentVersion, int? versionCode = null, string? userId = null, CancellationToken cancellationToken = default)
    {
        var effectiveUserId = string.IsNullOrWhiteSpace(userId) ? UserId : userId;
        var payload = new UpdateCheckRequest
        {
            ChannelCode = Channel,
            CurrentVersion = currentVersion,
            VersionCode = versionCode,
            Platform = Platform,
            Arch = Arch,
            DeviceId = DeviceId,
            UserId = string.IsNullOrWhiteSpace(effectiveUserId) ? null : effectiveUserId,
            Attributes = JsonDefaults.ToJsonElementMap(Attributes)
        };
        using var res = await DoRequestAsync(HttpMethod.Post, "/api/client/update-check", JsonDefaults.ToJsonContent(payload, SwmJsonContext.Default.UpdateCheckRequest), cancellationToken).ConfigureAwait(false);
        await SwmErrorParser.ThrowIfErrorAsync(res, cancellationToken).ConfigureAwait(false);
        var data = await JsonDefaults.DeserializeAsync(res.Content, SwmJsonContext.Default.UpdateCheckResponse, cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(data.Signature) && !string.IsNullOrWhiteSpace(data.ChecksumSha256))
        {
            if (!VerifySignatureInternal(data.ChecksumSha256!, data.Signature!))
            {
                throw new SwmApiException(0, null, "signature verification failed");
            }
        }
        return data;
    }

    public async Task ReportEventAsync(string eventName, Dictionary<string, object?>? properties = null, CancellationToken cancellationToken = default)
    {
        var payload = new EventIngestItem
        {
            DeviceId = DeviceId,
            EventName = eventName,
            EventTime = DateTime.UtcNow,
            ChannelCode = Channel,
            Properties = properties != null ? JsonDefaults.ToJsonElementMap(properties) : new Dictionary<string, JsonElement>(),
            Attributes = JsonDefaults.ToJsonElementMap(Attributes)
        };
        using var res = await DoRequestAsync(HttpMethod.Post, "/api/client/events", JsonDefaults.ToJsonContent(payload, SwmJsonContext.Default.EventIngestItem), cancellationToken).ConfigureAwait(false);
        await SwmErrorParser.ThrowIfErrorAsync(res, cancellationToken).ConfigureAwait(false);
    }

    public async Task ReportEventsAsync(List<EventIngestItem> events, CancellationToken cancellationToken = default)
    {
        var payload = new EventBatchRequest
        {
            Events = events
        };
        using var res = await DoRequestAsync(HttpMethod.Post, "/api/client/events", JsonDefaults.ToJsonContent(payload, SwmJsonContext.Default.EventBatchRequest), cancellationToken).ConfigureAwait(false);
        await SwmErrorParser.ThrowIfErrorAsync(res, cancellationToken).ConfigureAwait(false);
    }

    public async Task ReportHeartbeatAsync(string? appVersion = null, string? userId = null, CancellationToken cancellationToken = default)
    {
        var effectiveUserId = string.IsNullOrWhiteSpace(userId) ? UserId : userId;
        if (string.IsNullOrWhiteSpace(DeviceId))
        {
            throw new SwmValidationException(400, null, "device_id required");
        }
        var payload = new HeartbeatRequest
        {
            DeviceId = DeviceId,
            ChannelCode = string.IsNullOrWhiteSpace(Channel) ? null : Channel,
            AppVersion = appVersion,
            Platform = string.IsNullOrWhiteSpace(Platform) ? null : Platform,
            Arch = string.IsNullOrWhiteSpace(Arch) ? null : Arch,
            UserId = string.IsNullOrWhiteSpace(effectiveUserId) ? null : effectiveUserId,
            Attributes = Attributes.Count > 0 ? JsonDefaults.ToJsonElementMap(Attributes) : null
        };

        using var res = await DoRequestAsync(HttpMethod.Post, "/api/client/heartbeat", JsonDefaults.ToJsonContent(payload, SwmJsonContext.Default.HeartbeatRequest), cancellationToken).ConfigureAwait(false);
        await SwmErrorParser.ThrowIfErrorAsync(res, cancellationToken).ConfigureAwait(false);
    }

    public async Task ReportFeedbackAsync(string content, int? rating = null, string? contact = null, IEnumerable<string>? attachments = null, Dictionary<string, object?>? metadata = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(content))
        {
            throw new SwmValidationException(400, null, "content required");
        }

        var formResult = await MultipartBuilder.BuildFeedbackFormAsync(this, content, rating, contact, attachments, metadata).ConfigureAwait(false);
        using var form = formResult.Form;
        try
        {
            using var res = await DoRequestAsync(HttpMethod.Post, "/api/client/feedback", form, cancellationToken).ConfigureAwait(false);
            await SwmErrorParser.ThrowIfErrorAsync(res, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            foreach (var stream in formResult.Streams)
            {
                stream.Dispose();
            }
        }
    }

    public async Task DownloadAsync(string url, string destPath, string? checksum = null, string? signature = null, Action<long, long>? progress = null, CancellationToken cancellationToken = default)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        using var res = await HttpClient.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        await SwmErrorParser.ThrowIfErrorAsync(res, cancellationToken).ConfigureAwait(false);

        var directory = Path.GetDirectoryName(destPath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        using var source = await res.Content.ReadAsStreamAsync().ConfigureAwait(false);
        using var target = File.Create(destPath);
        using var sha = SHA256.Create();

        var buffer = new byte[32 * 1024];
        long written = 0;
        var total = res.Content.Headers.ContentLength ?? 0;
        while (true)
        {
            var read = await source.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }
            await target.WriteAsync(buffer, 0, read, cancellationToken).ConfigureAwait(false);
            sha.TransformBlock(buffer, 0, read, null, 0);
            written += read;
            progress?.Invoke(written, total);
        }
        sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

        if (!string.IsNullOrWhiteSpace(checksum))
        {
            var got = HexLower(sha.Hash ?? Array.Empty<byte>());
            if (!string.Equals(got, checksum, StringComparison.OrdinalIgnoreCase))
            {
                throw new SwmApiException(0, null, $"checksum mismatch: {got} != {checksum}");
            }
        }

        if (!string.IsNullOrWhiteSpace(signature) && !string.IsNullOrWhiteSpace(checksum))
        {
            if (!VerifySignatureInternal(checksum!, signature!))
            {
                throw new SwmApiException(0, null, "signature verification failed");
            }
        }
    }
}
