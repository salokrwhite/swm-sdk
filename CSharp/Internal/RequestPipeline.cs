using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace SwmSdk.Internal;

internal sealed class RequestPipeline : IDisposable
{
    private const string HeaderAppId = "X-App-Id";
    private const string HeaderTimestamp = "X-Timestamp";
    private const string HeaderNonce = "X-Nonce";
    private const string HeaderCapability = "X-Authz-Capability";
    private const string HeaderReleaseId = "X-Client-Release-Id";
    private const string HeaderClientVersion = "X-Client-Version";
    private const string HeaderClientVersionCode = "X-Client-Version-Code";
    private const string HeaderSession = "X-SWM-Session";
    private const string HeaderDpop = "X-SWM-DPoP";
    private const string HeaderBodyEncryption = "X-SWM-Body-Enc";
    private const string HeaderOnlineKeyId = "X-SWM-Online-Key-Id";
    private const string BodyEncryptionVersion = "x25519-aes-gcm-v1";
    private const int MaximumPreviousKeys = 4;
    private const int OnlineKeyRefreshLeadSeconds = 5 * 60;

    private readonly object _keySync = new();
    private readonly SemaphoreSlim _keyRefreshLock = new(1, 1);
    private readonly SwmClientOptions _options;
    private readonly StateStore _stateStore;
    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;
    private readonly TrustedClock _clock = new();
    private readonly List<ProtocolKey> _previousKeys = [];
    private DeviceIdentity? _identity;
    private HardwareEvidence? _hardwareEvidence;
    private OfflineBudgetState? _offlineBudget;
    private ProtocolKey? _currentKey;
    private string? _session;
    private long _sessionExpiresAt;
    private bool _disposed;

    public RequestPipeline(SwmClientOptions options)
    {
        _options = options;
        _stateStore = new StateStore(options.AppId, options.StorageDirectory);
        if (options.HttpMessageHandler != null)
        {
            _httpClient = new HttpClient(options.HttpMessageHandler, disposeHandler: false);
        }
        else
        {
            _httpClient = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
            _ownsHttpClient = true;
        }
        _httpClient.Timeout = Timeout.InfiniteTimeSpan;
        _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
    }

    public string DeviceId => string.IsNullOrWhiteSpace(_options.DeviceId)
        ? GetIdentity().DeviceId
        : _options.DeviceId.Trim();
    public string InstallId => GetIdentity().InstallId;
    public string DeviceKeyId => GetIdentity().KeyId;
    public string KeyThumbprint => GetIdentity().KeyThumbprint;
    public string PublicKeySec1 => GetIdentity().PublicKeySec1;
    public TrustedClock Clock => _clock;
    public StateStore StateStore => _stateStore;
    public string? SessionToken => _session;
    public long SessionExpiresAt => _sessionExpiresAt;
    public bool HostIntegrityRequired { get; private set; }
    public IntegrityFailureAction LastFailureAction { get; private set; } = IntegrityFailureAction.DenyOperations;

    public void SetHostIntegrityPolicy(bool required)
    {
        HostIntegrityRequired = required;
    }

    public bool HasValidSession()
    {
        var now = _clock.IsInitialized
            ? _clock.NowUnixSeconds
            : DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        return !string.IsNullOrWhiteSpace(_session) && _sessionExpiresAt > now;
    }

    public bool IsOfflineBudgetLocked()
    {
        return GetOfflineBudget().IsLocked(_clock);
    }

    public void ClearSession()
    {
        _session = null;
        _sessionExpiresAt = 0;
    }

    public DeviceAuthRegistration CreateDeviceAuth(string? challenge = null)
    {
        return CreateDeviceAuth(GetIdentity(), challenge);
    }

    private DeviceAuthRegistration CreateDeviceAuth(DeviceIdentity identity, string? challenge)
    {
        var hardware = GetHardwareEvidence();
        return new DeviceAuthRegistration
        {
            InstallId = identity.InstallId,
            KeyId = identity.KeyId,
            KeyThumbprint = identity.KeyThumbprint,
            PublicKeySec1 = identity.PublicKeySec1,
            CredentialVersion = DeviceIdentity.CredentialVersion,
            Challenge = challenge,
            HardwareEvidence = new HardwareEvidence
            {
                Version = hardware.Version,
                ComponentMask = hardware.ComponentMask,
                AggregateHash = hardware.AggregateHash
            }
        };
    }

    public async Task<DeviceKeyRotationResult> RotateDeviceKeyAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        if (_clock.IsInitialized == false)
        {
            await RefreshTrustedTimeCoreAsync(cancellationToken).ConfigureAwait(false);
        }
        await RefreshOnlineKeysAsync(force: false, cancellationToken).ConfigureAwait(false);
        EnsureSession();
        var pending = DeviceIdentity.CreatePending(_options.AppId, _stateStore);
        var committed = false;
        try
        {
            string? challenge = null;
            string? proofDigest = null;
            for (var attempt = 0; attempt < 2; attempt++)
            {
                var payload = new DeviceKeyRotationRequest
                {
                    NewDeviceAuth = CreateDeviceAuth(pending, challenge),
                    NewKeyProof = null
                };
                if (challenge != null && proofDigest != null)
                {
                    var digest = Convert.FromHexString(proofDigest);
                    if (digest.Length != 32)
                    {
                        throw new SwmProtocolException("device key rotation proof digest is invalid");
                    }
                    payload.NewKeyProof = CryptoUtil.Base64UrlEncode(pending.SignSha256(digest));
                }
                var response = await SendAsync(
                    new ProtocolRequest(
                        HttpMethod.Post,
                        "/api/client/device-key/rotate",
                        SwmOperationClass.DeviceKeyRotation,
                        JsonUtil.SerializeToUtf8(payload),
                        EncryptBody: true,
                        RequireSession: true,
                        RequireTrustedTime: true,
                        RequireOnlineKey: true),
                    cancellationToken).ConfigureAwait(false);
                if (response.StatusCode == 428 && attempt == 0)
                {
                    var rotationChallenge = JsonUtil.Deserialize<DeviceKeyRotationChallengeResponse>(response.Body);
                    if (string.IsNullOrWhiteSpace(rotationChallenge.Challenge) ||
                        string.IsNullOrWhiteSpace(rotationChallenge.ProofDigest) ||
                        rotationChallenge.ExpiresAt <= _clock.NowUnixSeconds)
                    {
                        throw new SwmProtocolException("device key rotation challenge is invalid");
                    }
                    challenge = rotationChallenge.Challenge;
                    proofDigest = rotationChallenge.ProofDigest;
                    continue;
                }
                ThrowIfError(response);
                var result = JsonUtil.Deserialize<DeviceKeyRotationResponse>(response.Body);
                if (!result.Rotated ||
                    !Guid.TryParse(result.RegistrationId, out _) ||
                    result.InstallId != pending.InstallId ||
                    result.KeyId != pending.KeyId)
                {
                    throw new SwmProtocolException("device key rotation response is invalid");
                }
                pending.CommitPending();
                committed = true;
                _identity?.Dispose();
                _identity = pending;
                _offlineBudget = null;
                ClearSession();
                return new DeviceKeyRotationResult
                {
                    RegistrationId = result.RegistrationId!,
                    InstallId = pending.InstallId,
                    KeyId = pending.KeyId,
                    DeviceId = DeviceId
                };
            }
            throw new SwmProtocolException("device key rotation challenge retry was exhausted");
        }
        catch
        {
            if (!committed)
            {
                pending.DeletePending();
            }
            throw;
        }
    }

    public string GetTrustedNowSeconds()
    {
        var value = _clock.NowUnixSeconds;
        if (value <= 0)
        {
            throw new SwmClockException("trusted server time is unavailable");
        }
        return value.ToString(CultureInfo.InvariantCulture);
    }

    public async Task RefreshOnlineKeysAsync(bool force, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (!force && HasFreshOnlineKey())
        {
            return;
        }
        await _keyRefreshLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!force && HasFreshOnlineKey())
            {
                return;
            }
            try
            {
                if (!_clock.IsInitialized)
                {
                    await RefreshTrustedTimeCoreAsync(cancellationToken).ConfigureAwait(false);
                }
                await RefreshOnlineKeysCoreAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (
                ex is SwmNetworkException or SwmTimeoutException ||
                ex is SwmApiException { StatusCode: >= 500 })
            {
                if (!CanUseCurrentKeyAfterRefreshFailure())
                {
                    throw;
                }
            }
        }
        finally
        {
            _keyRefreshLock.Release();
        }
    }

    public async Task SyncServerTimeAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        await RefreshTrustedTimeCoreAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<ProtocolResponse> SendAsync(
        ProtocolRequest request,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (request.RequireTrustedTime && !_clock.IsInitialized)
        {
            await RefreshTrustedTimeCoreAsync(cancellationToken).ConfigureAwait(false);
        }
        if (request.RequireOnlineKey)
        {
            await RefreshOnlineKeysAsync(force: false, cancellationToken).ConfigureAwait(false);
        }
        if (request.RequireSession)
        {
            EnsureSession();
        }

        var policy = RequestPolicies.Resolve(request.Operation);
        var started = Stopwatch.GetTimestamp();
        Exception? lastTransport = null;

        for (var attempt = 0; attempt <= policy.Retries; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (policy.DeadlineMilliseconds > 0 &&
                ElapsedMilliseconds(started) + policy.TimeoutMilliseconds > policy.DeadlineMilliseconds)
            {
                break;
            }

            try
            {
                var response = await SendAttemptAsync(request, policy, cancellationToken).ConfigureAwait(false);
                if (IsTransientStatus(response.StatusCode) && attempt < policy.Retries)
                {
                    var retryAfter = ParseRetryAfter(response);
                    var delay = retryAfter ?? Backoff(policy, attempt);
                    if (!CanWait(policy, started, delay, attempt))
                    {
                        return response;
                    }
                    await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                    continue;
                }
                return response;
            }
            catch (Exception ex) when (ex is HttpRequestException or IOException or TaskCanceledException)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                lastTransport = ex;
                if (attempt >= policy.Retries)
                {
                    break;
                }
                var delay = Backoff(policy, attempt);
                if (!CanWait(policy, started, delay, attempt))
                {
                    break;
                }
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            }
        }

        if (lastTransport is TaskCanceledException)
        {
            throw new SwmTimeoutException("request timed out", lastTransport);
        }
        if (lastTransport != null)
        {
            throw new SwmNetworkException("network request failed", lastTransport);
        }
        throw new SwmTimeoutException("request deadline exceeded", new TimeoutException());
    }

    public async Task<T> SendAndVerifyAsync<T>(
        ProtocolRequest request,
        CancellationToken cancellationToken = default)
    {
        var response = await SendAsync(request, cancellationToken).ConfigureAwait(false);
        ThrowIfError(response);
        return VerifyAuthz<T>(response, response.RequestNonce);
    }

    public T VerifyAuthz<T>(ProtocolResponse response, string requestNonce)
    {
        if (!JsonUtil.TryGetRawData(response.Body, out var data, out var authzRaw))
        {
            throw new SwmProtocolException("Authz v3 carrier is missing data or authz");
        }
        var envelope = JsonSerializer.Deserialize<AuthzV3Envelope>(authzRaw!, JsonUtil.Options)
            ?? throw new SwmProtocolException("Authz v3 envelope is empty");
        VerifyAuthzEnvelope(envelope, requestNonce, data);
        return JsonSerializer.Deserialize<T>(data, JsonUtil.Options)
            ?? throw new SwmProtocolException("verified response data is empty");
    }

    public void ThrowIfError(ProtocolResponse response)
    {
        if (response.StatusCode is >= 200 and < 300)
        {
            return;
        }

        var bodyText = Encoding.UTF8.GetString(response.Body);
        var code = string.Empty;
        var message = ((HttpStatusCode)response.StatusCode).ToString();
        string? minimumVersion = null;
        var failureAction = IntegrityFailureAction.ShutdownClient;
        try
        {
            using var document = JsonDocument.Parse(response.Body);
            var root = document.RootElement;
            if (root.TryGetProperty("error", out var error))
            {
                if (error.ValueKind == JsonValueKind.String)
                {
                    message = error.GetString() ?? message;
                    if (LooksLikeCode(message))
                    {
                        code = message;
                    }
                }
                else if (error.ValueKind == JsonValueKind.Object)
                {
                    if (error.TryGetProperty("code", out var codeNode))
                    {
                        code = codeNode.GetString() ?? string.Empty;
                    }
                    if (error.TryGetProperty("message", out var messageNode))
                    {
                        message = messageNode.GetString() ?? code;
                    }
                    else if (!string.IsNullOrWhiteSpace(code))
                    {
                        message = code;
                    }
                    if (error.TryGetProperty("minimum_supported_version", out var minimumNode))
                    {
                        minimumVersion = minimumNode.GetString();
                    }
                    if (error.TryGetProperty("failure_action", out var actionNode))
                    {
                        failureAction = actionNode.GetString() switch
                        {
                            "deny_operations" => IntegrityFailureAction.DenyOperations,
                            _ => IntegrityFailureAction.ShutdownClient
                        };
                        LastFailureAction = failureAction;
                    }
                }
            }
            else if (root.TryGetProperty("code", out var rootCode))
            {
                code = rootCode.GetString() ?? string.Empty;
                if (root.TryGetProperty("message", out var rootMessage))
                {
                    message = rootMessage.GetString() ?? message;
                }
            }
        }
        catch
        {
            if (!string.IsNullOrWhiteSpace(bodyText))
            {
                message = bodyText.Length <= 1024 ? bodyText : bodyText[..1024];
            }
        }

        if (string.Equals(code, SwmDeviceBlockedException.Code, StringComparison.OrdinalIgnoreCase))
        {
            throw new SwmDeviceBlockedException(response.StatusCode, message, bodyText);
        }
        if (string.Equals(code, SwmUnsupportedVersionException.Code, StringComparison.OrdinalIgnoreCase))
        {
            throw new SwmUnsupportedVersionException(response.StatusCode, message, minimumVersion, bodyText);
        }
        if (string.Equals(code, SwmUpdateRegionBlockedException.Code, StringComparison.OrdinalIgnoreCase))
        {
            throw new SwmUpdateRegionBlockedException(response.StatusCode, message, bodyText);
        }
        if (string.Equals(code, SwmFeedbackDisabledException.Code, StringComparison.OrdinalIgnoreCase))
        {
            throw new SwmFeedbackDisabledException(response.StatusCode, message, bodyText);
        }
        if (code.StartsWith("release_integrity_", StringComparison.Ordinal))
        {
            throw new SwmIntegrityException(response.StatusCode, code, message, failureAction, bodyText);
        }
        if (code.StartsWith("operation_auth_", StringComparison.Ordinal) ||
            code.StartsWith("operation_grant_", StringComparison.Ordinal))
        {
            throw new SwmOperationAuthorizationException(response.StatusCode, code, message, bodyText);
        }
        if (response.StatusCode == 429)
        {
            throw new SwmRateLimitException(response.StatusCode, message, ParseRetryAfter(response), bodyText);
        }
        if (response.StatusCode is 401)
        {
            throw new SwmSessionException(response.StatusCode, code, message, bodyText);
        }
        if (response.StatusCode is 403)
        {
            throw new SwmUnauthorizedException(response.StatusCode, code, message, bodyText);
        }
        if (response.StatusCode is >= 400 and < 500)
        {
            throw new SwmValidationException(response.StatusCode, code, message, bodyText);
        }
        throw new SwmApiException(response.StatusCode, code, message, bodyText);
    }

    public string CreateDpopProof(
        string method,
        string absoluteUrl,
        string sessionBinding,
        ReadOnlySpan<byte> body)
    {
        var now = _clock.NowUnixSeconds;
        if (now <= 0)
        {
            throw new SwmClockException("trusted server time is unavailable");
        }
        var header = JsonUtil.ToJsonString(new Dictionary<string, string>
        {
            ["alg"] = "ES256",
            ["kid"] = DeviceKeyId,
            ["typ"] = "swm-dpop+jwt"
        });
        var payload = JsonUtil.ToJsonString(new Dictionary<string, object>
        {
            ["app_id"] = _options.AppId,
            ["ath"] = CryptoUtil.Base64UrlEncode(CryptoUtil.Sha256(Encoding.UTF8.GetBytes(sessionBinding))),
            ["body_sha256"] = CryptoUtil.Sha256Hex(body),
            ["channel"] = _options.Channel,
            ["device_id"] = DeviceId,
            ["exp"] = now + 60,
            ["htm"] = method.ToUpperInvariant(),
            ["htu"] = absoluteUrl,
            ["iat"] = now,
            ["install_id"] = InstallId,
            ["jti"] = Convert.ToHexString(CryptoUtil.RandomBytes(16)).ToLowerInvariant(),
            ["pcid"] = DeviceId,
            ["release_id"] = _options.ReleaseId
        });
        var encodedHeader = CryptoUtil.Base64UrlEncode(Encoding.UTF8.GetBytes(header));
        var encodedPayload = CryptoUtil.Base64UrlEncode(Encoding.UTF8.GetBytes(payload));
        var signingInput = encodedHeader + "." + encodedPayload;
        var signature = GetIdentity().SignSha256(CryptoUtil.Sha256(Encoding.UTF8.GetBytes(signingInput)));
        if (signature.Length != 64)
        {
            throw new SwmCryptographicException("DPoP signer returned an invalid signature length");
        }
        return signingInput + "." + CryptoUtil.Base64UrlEncode(signature);
    }

    public async Task<HttpResponseMessage> SendDownloadAsync(
        Uri url,
        long? rangeStart,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        if (!_clock.IsInitialized)
        {
            await RefreshTrustedTimeCoreAsync(cancellationToken).ConfigureAwait(false);
        }
        var session = EnsureSession();
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        if (rangeStart is > 0)
        {
            request.Headers.Range = new RangeHeaderValue(rangeStart.Value, null);
        }
        request.Headers.TryAddWithoutValidation(HeaderSession, session);
        request.Headers.TryAddWithoutValidation(
            HeaderDpop,
            CreateDpopProof(HttpMethod.Get.Method, url.AbsoluteUri, session, ReadOnlySpan<byte>.Empty));
        return await _httpClient.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<HttpResponseMessage> SendStorageRequestAsync(
        Uri url,
        long? rangeStart,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        if (url.Scheme != Uri.UriSchemeHttps && !_options.AllowInsecureHttp)
        {
            throw new SwmNetworkException(
                "storage redirect must use HTTPS",
                new InvalidOperationException("insecure storage redirect"));
        }
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        if (rangeStart is > 0)
        {
            request.Headers.Range = new RangeHeaderValue(rangeStart.Value, null);
        }
        return await _httpClient.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<(HttpResponseMessage Response, string RequestNonce)> SendUpdateStreamAsync(
        Uri url,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        if (!_clock.IsInitialized)
        {
            await RefreshTrustedTimeCoreAsync(cancellationToken).ConfigureAwait(false);
        }
        var session = EnsureSession();
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        var requestNonce = Guid.NewGuid().ToString("D");
        request.Headers.Accept.ParseAdd("text/event-stream");
        request.Headers.TryAddWithoutValidation(HeaderAppId, _options.AppId);
        request.Headers.TryAddWithoutValidation(
            HeaderTimestamp,
            _clock.NowUnixSeconds.ToString(CultureInfo.InvariantCulture));
        request.Headers.TryAddWithoutValidation(HeaderNonce, requestNonce);
        request.Headers.TryAddWithoutValidation(HeaderCapability, "v3");
        request.Headers.TryAddWithoutValidation(HeaderReleaseId, _options.ReleaseId);
        request.Headers.TryAddWithoutValidation(HeaderClientVersion, _options.Version);
        request.Headers.TryAddWithoutValidation(
            HeaderClientVersionCode,
            _options.VersionCode?.ToString(CultureInfo.InvariantCulture) ?? string.Empty);
        request.Headers.TryAddWithoutValidation(HeaderSession, session);
        request.Headers.TryAddWithoutValidation(
            HeaderDpop,
            CreateDpopProof(HttpMethod.Get.Method, url.AbsoluteUri, session, ReadOnlySpan<byte>.Empty));
        var response = await _httpClient.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);
        return (response, requestNonce);
    }

    public Task<ProtocolResponse> SendFirmwareResolveAsync(
        byte[] body,
        CancellationToken cancellationToken)
    {
        return SendWebOperationAsync(
            HttpMethod.Post,
            "/api/v1/device-models/resolve",
            body,
            SwmOperationClass.FirmwareIdentity,
            DebugCredentials: null,
            WatchToken: null,
            RequestId: null,
            cancellationToken);
    }

    public Task<ProtocolResponse> EnrollDebugClientAsync(
        byte[] body,
        CancellationToken cancellationToken)
    {
        return SendWebPublicAsync(
            "/api/v1/client/debug-enroll",
            body,
            SwmOperationClass.DebugProtocol,
            cancellationToken);
    }

    public Task<ProtocolResponse> CreateDebugRequestAsync(
        DebugCredentials credentials,
        byte[] body,
        CancellationToken cancellationToken)
    {
        return SendWebOperationAsync(
            HttpMethod.Post,
            "/api/v1/client/debug-requests",
            body,
            SwmOperationClass.DebugProtocol,
            credentials,
            WatchToken: null,
            RequestId: null,
            cancellationToken);
    }

    public Task<ProtocolResponse> CancelDebugRequestAsync(
        DebugCredentials credentials,
        string requestId,
        string watchToken,
        CancellationToken cancellationToken)
    {
        return SendWebOperationAsync(
            HttpMethod.Post,
            $"/api/v1/client/debug-requests/{requestId}/cancel",
            Array.Empty<byte>(),
            SwmOperationClass.DebugProtocol,
            credentials,
            watchToken,
            requestId,
            cancellationToken);
    }

    public Task<(HttpResponseMessage Response, string RequestNonce)> OpenDebugEventStreamAsync(
        DebugCredentials credentials,
        string requestId,
        string watchToken,
        CancellationToken cancellationToken)
    {
        return OpenDebugEventStreamCoreAsync(credentials, requestId, watchToken, cancellationToken);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        _identity?.Dispose();
        _keyRefreshLock.Dispose();
        if (_ownsHttpClient)
        {
            _httpClient.Dispose();
        }
    }

    private async Task<ProtocolResponse> SendAttemptAsync(
        ProtocolRequest request,
        RequestPolicy policy,
        CancellationToken cancellationToken)
    {
        var timestamp = request.RequireTrustedTime
            ? GetTrustedNowSeconds()
            : DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
        var nonce = Guid.NewGuid().ToString("D");
        var uri = BuildUri(request.Path, request.Query);
        var body = request.Body ?? Array.Empty<byte>();
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [HeaderAppId] = _options.AppId,
            [HeaderTimestamp] = timestamp,
            [HeaderNonce] = nonce,
            [HeaderCapability] = "v3",
            [HeaderReleaseId] = _options.ReleaseId,
            [HeaderClientVersion] = _options.Version,
            [HeaderClientVersionCode] = _options.VersionCode?.ToString(CultureInfo.InvariantCulture) ?? string.Empty
        };

        using var httpRequest = new HttpRequestMessage(request.Method, uri);
        if (request.RequireOnlineKey)
        {
            var key = GetCurrentKey();
            var sessionBinding = request.RequireSession ? EnsureSession() : string.Empty;
            headers[HeaderDpop] = CreateDpopProof(
                request.Method.Method,
                request.DpopResource ?? uri.AbsoluteUri,
                sessionBinding,
                body);
            if (request.RequireSession)
            {
                headers[HeaderSession] = sessionBinding;
            }
            if (request.EncryptBody)
            {
                var encrypted = CryptoUtil.EncryptRequestBody(
                    request.Method.Method,
                    uri.AbsolutePath,
                    BuildCanonicalQuery(uri.Query),
                    long.Parse(timestamp, CultureInfo.InvariantCulture),
                    nonce,
                    _options.AppId,
                    _options.ReleaseId,
                    _options.Version,
                    _options.VersionCode?.ToString(CultureInfo.InvariantCulture),
                    key.KeyId,
                    key.PublicKey,
                    body);
                httpRequest.Content = new ByteArrayContent(encrypted);
                if (!string.IsNullOrWhiteSpace(request.ContentType))
                {
                    httpRequest.Content.Headers.TryAddWithoutValidation("Content-Type", request.ContentType);
                }
                headers[HeaderBodyEncryption] = BodyEncryptionVersion;
                headers[HeaderOnlineKeyId] = key.KeyId;
            }
            else if (body.Length > 0)
            {
                httpRequest.Content = new ByteArrayContent(body);
                if (!string.IsNullOrWhiteSpace(request.ContentType))
                {
                    httpRequest.Content.Headers.TryAddWithoutValidation("Content-Type", request.ContentType);
                }
            }
        }

        foreach (var pair in headers)
        {
            httpRequest.Headers.TryAddWithoutValidation(pair.Key, pair.Value);
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (policy.TimeoutMilliseconds > 0)
        {
            timeout.CancelAfter(policy.TimeoutMilliseconds);
        }
        using var response = await _httpClient.SendAsync(
            httpRequest,
            HttpCompletionOption.ResponseHeadersRead,
            timeout.Token).ConfigureAwait(false);
        var responseBody = await ReadBoundedAsync(response.Content, 16 * 1024 * 1024, timeout.Token)
            .ConfigureAwait(false);
        var responseHeaders = response.Headers.ToDictionary(
            pair => pair.Key,
            pair => pair.Value.ToArray(),
            StringComparer.OrdinalIgnoreCase);
        return new ProtocolResponse((int)response.StatusCode, responseBody, nonce, responseHeaders);
    }

    private async Task<ProtocolResponse> SendWebOperationAsync(
        HttpMethod method,
        string path,
        byte[] body,
        SwmOperationClass operation,
        DebugCredentials? DebugCredentials,
        string? WatchToken,
        string? RequestId,
        CancellationToken cancellationToken)
    {
        if (!_clock.IsInitialized)
        {
            await RefreshTrustedTimeCoreAsync(cancellationToken).ConfigureAwait(false);
        }
        var session = EnsureSession();
        var policy = RequestPolicies.Resolve(operation);
        var started = Stopwatch.GetTimestamp();
        Exception? lastError = null;
        for (var attempt = 0; attempt <= policy.Retries; attempt++)
        {
            try
            {
                var response = await SendWebAttemptAsync(
                    method,
                    path,
                    body,
                    session,
                    DebugCredentials,
                    WatchToken,
                    policy,
                    cancellationToken).ConfigureAwait(false);
                if (response.StatusCode is >= 200 and < 400)
                {
                    return response;
                }
                if (IsTransientStatus(response.StatusCode) && attempt < policy.Retries)
                {
                    var delay = ParseRetryAfter(response) ?? Backoff(policy, attempt);
                    if (!CanWait(policy, started, delay, attempt))
                    {
                        return response;
                    }
                    await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                    continue;
                }
                return response;
            }
            catch (Exception ex) when (ex is HttpRequestException or IOException or TaskCanceledException)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                lastError = ex;
                if (attempt >= policy.Retries)
                {
                    break;
                }
                var delay = Backoff(policy, attempt);
                if (!CanWait(policy, started, delay, attempt))
                {
                    break;
                }
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            }
        }
        throw new SwmNetworkException("web protocol request failed", lastError ?? new IOException("request failed"));
    }

    private async Task<ProtocolResponse> SendWebPublicAsync(
        string path,
        byte[] body,
        SwmOperationClass operation,
        CancellationToken cancellationToken)
    {
        var policy = RequestPolicies.Resolve(operation);
        var uri = BuildWebUri(path);
        Exception? lastError = null;
        for (var attempt = 0; attempt <= policy.Retries; attempt++)
        {
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, uri);
                request.Content = new ByteArrayContent(body);
                request.Content.Headers.TryAddWithoutValidation("Content-Type", "application/json; charset=utf-8");
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(policy.TimeoutMilliseconds);
                using var response = await _httpClient.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    timeout.Token).ConfigureAwait(false);
                var responseBody = await ReadBoundedAsync(response.Content, 4 * 1024 * 1024, timeout.Token)
                    .ConfigureAwait(false);
                var result = new ProtocolResponse(
                    (int)response.StatusCode,
                    responseBody,
                    Guid.NewGuid().ToString("D"),
                    response.Headers.ToDictionary(
                        pair => pair.Key,
                        pair => pair.Value.ToArray(),
                        StringComparer.OrdinalIgnoreCase));
                if (result.StatusCode is >= 200 and < 400 ||
                    !IsTransientStatus(result.StatusCode) ||
                    attempt >= policy.Retries)
                {
                    return result;
                }
                await Task.Delay(Backoff(policy, attempt), cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is HttpRequestException or IOException or TaskCanceledException)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                lastError = ex;
                if (attempt >= policy.Retries)
                {
                    break;
                }
                await Task.Delay(Backoff(policy, attempt), cancellationToken).ConfigureAwait(false);
            }
        }
        throw new SwmNetworkException("public web request failed", lastError ?? new IOException("request failed"));
    }

    private async Task<ProtocolResponse> SendWebAttemptAsync(
        HttpMethod method,
        string path,
        byte[] body,
        string session,
        DebugCredentials? debugCredentials,
        string? watchToken,
        RequestPolicy policy,
        CancellationToken cancellationToken)
    {
        var uri = BuildWebUri(path);
        using var request = new HttpRequestMessage(method, uri);
        request.Headers.TryAddWithoutValidation(HeaderSession, session);
        request.Headers.TryAddWithoutValidation(
            HeaderDpop,
            CreateDpopProof(method.Method, uri.AbsoluteUri, session, body));
        if (body.Length > 0)
        {
            request.Content = new ByteArrayContent(body);
            request.Content.Headers.TryAddWithoutValidation("Content-Type", "application/json; charset=utf-8");
        }
        if (debugCredentials != null)
        {
            var timestamp = GetTrustedNowSeconds();
            var nonce = Convert.ToHexString(CryptoUtil.RandomBytes(16)).ToLowerInvariant();
            var signature = CreateDebugHmac(
                debugCredentials.ClientSecret,
                method.Method,
                uri.AbsolutePath,
                body,
                timestamp,
                nonce,
                debugCredentials.ClientId);
            request.Headers.TryAddWithoutValidation("X-Client-ID", debugCredentials.ClientId);
            request.Headers.TryAddWithoutValidation("X-Timestamp", timestamp);
            request.Headers.TryAddWithoutValidation("X-Nonce", nonce);
            request.Headers.TryAddWithoutValidation("X-Signature-Version", "1");
            request.Headers.TryAddWithoutValidation("X-Signature", signature);
        }
        if (!string.IsNullOrWhiteSpace(watchToken))
        {
            request.Headers.TryAddWithoutValidation("X-Debug-Watch-Token", watchToken);
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(policy.TimeoutMilliseconds);
        using var response = await _httpClient.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            timeout.Token).ConfigureAwait(false);
        var responseBody = await ReadBoundedAsync(response.Content, 4 * 1024 * 1024, timeout.Token)
            .ConfigureAwait(false);
        return new ProtocolResponse(
            (int)response.StatusCode,
            responseBody,
            Guid.NewGuid().ToString("D"),
            response.Headers.ToDictionary(
                pair => pair.Key,
                pair => pair.Value.ToArray(),
                StringComparer.OrdinalIgnoreCase));
    }

    private async Task<(HttpResponseMessage Response, string RequestNonce)> OpenDebugEventStreamCoreAsync(
        DebugCredentials credentials,
        string requestId,
        string watchToken,
        CancellationToken cancellationToken)
    {
        if (!_clock.IsInitialized)
        {
            await RefreshTrustedTimeCoreAsync(cancellationToken).ConfigureAwait(false);
        }
        var session = EnsureSession();
        var path = $"/api/v1/client/debug-requests/{requestId}/events";
        var uri = BuildWebUri(path);
        var requestNonce = Convert.ToHexString(CryptoUtil.RandomBytes(16)).ToLowerInvariant();
        var timestamp = GetTrustedNowSeconds();
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.Accept.ParseAdd("text/event-stream");
        request.Headers.TryAddWithoutValidation("X-Client-ID", credentials.ClientId);
        request.Headers.TryAddWithoutValidation("X-Timestamp", timestamp);
        request.Headers.TryAddWithoutValidation("X-Nonce", requestNonce);
        request.Headers.TryAddWithoutValidation("X-Signature-Version", "1");
        request.Headers.TryAddWithoutValidation(
            "X-Signature",
            CreateDebugHmac(
                credentials.ClientSecret,
                "GET",
                uri.AbsolutePath,
                ReadOnlySpan<byte>.Empty,
                timestamp,
                requestNonce,
                credentials.ClientId));
        request.Headers.TryAddWithoutValidation(HeaderSession, session);
        request.Headers.TryAddWithoutValidation(
            HeaderDpop,
            CreateDpopProof("GET", uri.AbsoluteUri, session, ReadOnlySpan<byte>.Empty));
        request.Headers.TryAddWithoutValidation("X-Debug-Watch-Token", watchToken);
        var response = await _httpClient.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);
        return (response, requestNonce);
    }

    private async Task RefreshTrustedTimeCoreAsync(CancellationToken cancellationToken)
    {
        var request = new ProtocolRequest(
            HttpMethod.Get,
            "/api/client/time",
            SwmOperationClass.TrustedTimeSync,
            Body: null,
            EncryptBody: false,
            RequireSession: false,
            RequireTrustedTime: false,
            RequireOnlineKey: false);
        var started = TrustedClock.TickMilliseconds();
        var response = await SendAsync(request, cancellationToken).ConfigureAwait(false);
        var received = TrustedClock.TickMilliseconds();
        ThrowIfError(response);
        var manifest = JsonUtil.Deserialize<ServerTimeManifest>(response.Body);
        VerifyServerTimeManifest(manifest, response.RequestNonce);
        _clock.SetAuthoritativeTime(manifest.ServerTimeMs, started, received);
        NoteServerVerifiedInteraction();
    }

    private async Task RefreshOnlineKeysCoreAsync(CancellationToken cancellationToken)
    {
        var request = new ProtocolRequest(
            HttpMethod.Get,
            "/api/client/key-manifest",
            SwmOperationClass.OnlineKeyManifest,
            Body: null,
            EncryptBody: false,
            RequireSession: false,
            RequireTrustedTime: true,
            RequireOnlineKey: false);
        var response = await SendAsync(request, cancellationToken).ConfigureAwait(false);
        ThrowIfError(response);
        var manifest = JsonUtil.Deserialize<OnlineKeyManifest>(response.Body);
        VerifyOnlineKeyManifest(manifest);
        InstallKey(new ProtocolKey(
            manifest.KeyId!,
            manifest.PublicKey!,
            manifest.IssuedAt,
            manifest.RefreshAfter));
    }

    private void VerifyServerTimeManifest(ServerTimeManifest manifest, string expectedNonce)
    {
        if (manifest.ManifestVersion != "server_time_v1" ||
            manifest.AppId != _options.AppId ||
            manifest.ReleaseId != _options.ReleaseId ||
            manifest.Nonce != expectedNonce ||
            manifest.RootTrustKeyId != _options.RootTrustKeyId ||
            string.IsNullOrWhiteSpace(manifest.Signature) ||
            manifest.ServerTimeMs <= 0 ||
            manifest.ExpiresAtMs <= manifest.ServerTimeMs ||
            manifest.ExpiresAtMs - manifest.ServerTimeMs > 60000)
        {
            throw new SwmClockException("signed server time identity or lifetime is invalid");
        }
        var canonical = string.Join(
            "\n",
            "server_time_v1",
            "app_id:" + manifest.AppId,
            "release_id:" + manifest.ReleaseId,
            "nonce:" + manifest.Nonce,
            "server_time_ms:" + manifest.ServerTimeMs.ToString(CultureInfo.InvariantCulture),
            "expires_at_ms:" + manifest.ExpiresAtMs.ToString(CultureInfo.InvariantCulture),
            "root_trust_key_id:" + manifest.RootTrustKeyId);
        if (!CryptoUtil.VerifyEd25519(_options.RootTrustPublicKey, Encoding.UTF8.GetBytes(canonical), manifest.Signature!))
        {
            throw new SwmClockException("signed server time signature is invalid");
        }
    }

    private void VerifyOnlineKeyManifest(OnlineKeyManifest manifest)
    {
        if (manifest.ManifestVersion != "online_key_manifest_v1" ||
            manifest.Purpose != "online_body" ||
            manifest.AppId != _options.AppId ||
            manifest.ReleaseId != _options.ReleaseId ||
            manifest.RootTrustKeyId != _options.RootTrustKeyId ||
            string.IsNullOrWhiteSpace(manifest.KeyId) ||
            string.IsNullOrWhiteSpace(manifest.PublicKey) ||
            string.IsNullOrWhiteSpace(manifest.RootTrustSignature) ||
            manifest.IssuedAt <= 0 ||
            manifest.RefreshAfter <= manifest.IssuedAt ||
            manifest.RefreshAfter - manifest.IssuedAt > 30L * 24 * 60 * 60)
        {
            throw new SwmIntegrityException(
                0,
                "online_key_manifest_invalid",
                "online key manifest identity or lifetime is invalid",
                IntegrityFailureAction.DenyOperations);
        }
        var now = _clock.NowUnixSeconds;
        if (manifest.IssuedAt > now + 120 || manifest.RefreshAfter < now - 120)
        {
            throw new SwmIntegrityException(
                0,
                "online_key_manifest_invalid",
                "online key manifest is outside its accepted lifetime",
                IntegrityFailureAction.DenyOperations);
        }
        var canonical = string.Join(
            "\n",
            manifest.ManifestVersion,
            "purpose:" + manifest.Purpose,
            "app_id:" + manifest.AppId,
            "release_id:" + manifest.ReleaseId,
            "key_id:" + manifest.KeyId,
            "public_key:" + manifest.PublicKey,
            "root_trust_key_id:" + manifest.RootTrustKeyId,
            "issued_at:" + manifest.IssuedAt.ToString(CultureInfo.InvariantCulture),
            "refresh_after:" + manifest.RefreshAfter.ToString(CultureInfo.InvariantCulture));
        if (!CryptoUtil.VerifyEd25519(
                _options.RootTrustPublicKey,
                Encoding.UTF8.GetBytes(canonical),
                manifest.RootTrustSignature!))
        {
            throw new SwmIntegrityException(
                0,
                "online_key_manifest_invalid",
                "online key manifest root signature is invalid",
                IntegrityFailureAction.DenyOperations);
        }
    }

    private void VerifyAuthzEnvelope(AuthzV3Envelope envelope, string requestNonce, byte[] data)
    {
        var now = _clock.NowUnixSeconds;
        if (envelope.Version != "authz_v3" ||
            envelope.Decision != "allow" ||
            envelope.ReleaseId != _options.ReleaseId ||
            envelope.DeviceId != DeviceId ||
            envelope.Nonce != requestNonce ||
            string.IsNullOrWhiteSpace(envelope.KeyId) ||
            envelope.IssuedAt <= 0 ||
            envelope.ExpiresAt <= envelope.IssuedAt ||
            envelope.ExpiresAt - envelope.IssuedAt > 900 ||
            envelope.IssuedAt > now + 120 ||
            envelope.ExpiresAt < now - 120)
        {
            throw new SwmUnauthorizedException(403, "authz_invalid", "Authz v3 response identity or lifetime is invalid");
        }
        var key = FindKey(envelope.KeyId);
        if (key == null)
        {
            throw new SwmUnauthorizedException(403, "authz_invalid", "Authz v3 response key is unknown");
        }
        if (!string.Equals(
                envelope.DataSha256,
                CryptoUtil.Sha256Hex(data),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new SwmIntegrityException(
                403,
                "authz_data_mismatch",
                "Authz v3 response data hash is invalid",
                IntegrityFailureAction.ShutdownClient);
        }
        var canonical = string.Join(
            "\n",
            "authz_v3",
            "app_id:" + _options.AppId,
            "release_id:" + envelope.ReleaseId,
            "device_id:" + envelope.DeviceId,
            "nonce:" + envelope.Nonce,
            "decision:" + envelope.Decision,
            "reason:" + (envelope.Reason ?? string.Empty),
            "data_sha256:" + envelope.DataSha256,
            "session:" + (envelope.Session ?? string.Empty),
            "issued_at:" + envelope.IssuedAt.ToString(CultureInfo.InvariantCulture),
            "expires_at:" + envelope.ExpiresAt.ToString(CultureInfo.InvariantCulture),
            "key_id:" + envelope.KeyId);
        if (!CryptoUtil.VerifyEd25519(
                key.PublicKey,
                Encoding.UTF8.GetBytes(canonical),
                envelope.Signature ?? string.Empty))
        {
            throw new SwmIntegrityException(
                403,
                "authz_signature_invalid",
                "Authz v3 response signature is invalid",
                IntegrityFailureAction.ShutdownClient);
        }
        if (!string.IsNullOrWhiteSpace(envelope.Session))
        {
            _session = envelope.Session;
            _sessionExpiresAt = envelope.ExpiresAt;
        }
        NoteServerVerifiedInteraction();
    }

    private DeviceIdentity GetIdentity()
    {
        if (_identity != null)
        {
            return _identity;
        }
        _identity = DeviceIdentity.LoadOrCreate(_options.AppId, _stateStore);
        return _identity;
    }

    private OfflineBudgetState GetOfflineBudget()
    {
        var identity = GetIdentity();
        return _offlineBudget ??= new OfflineBudgetState(
            _stateStore,
            identity.InstallId,
            identity.KeyThumbprint);
    }

    private void NoteServerVerifiedInteraction()
    {
        var now = _clock.NowUnixMilliseconds;
        if (now > 0)
        {
            GetOfflineBudget().NoteVerifiedInteraction(now);
        }
    }

    private HardwareEvidence GetHardwareEvidence()
    {
        return _hardwareEvidence ??= HardwareEvidenceCollector.Collect(_options.AppId);
    }

    private bool HasFreshOnlineKey()
    {
        lock (_keySync)
        {
            return _currentKey != null &&
                _clock.IsInitialized &&
                _clock.NowUnixSeconds < _currentKey.RefreshAfter - OnlineKeyRefreshLeadSeconds;
        }
    }

    private ProtocolKey GetCurrentKey()
    {
        lock (_keySync)
        {
            if (_currentKey == null)
            {
                throw new SwmSessionException(401, "authz_key_required", "online authorization key is unavailable");
            }
            if (_clock.IsInitialized && _clock.NowUnixSeconds >= _currentKey.RefreshAfter)
            {
                throw new SwmSessionException(401, "authz_key_expired", "online authorization key has expired");
            }
            return _currentKey;
        }
    }

    private bool CanUseCurrentKeyAfterRefreshFailure()
    {
        lock (_keySync)
        {
            return _currentKey != null &&
                _clock.IsInitialized &&
                _clock.NowUnixSeconds < _currentKey.RefreshAfter;
        }
    }

    private ProtocolKey? FindKey(string keyId)
    {
        lock (_keySync)
        {
            if (_currentKey?.KeyId == keyId)
            {
                return _currentKey;
            }
            return _previousKeys.LastOrDefault(item => item.KeyId == keyId);
        }
    }

    private void InstallKey(ProtocolKey next)
    {
        lock (_keySync)
        {
            if (_currentKey?.KeyId == next.KeyId)
            {
                if (_currentKey.PublicKey != next.PublicKey)
                {
                    throw new SwmIntegrityException(
                        0,
                        "online_key_manifest_invalid",
                        "online key id was rebound to different key material",
                        IntegrityFailureAction.DenyOperations);
                }
                _currentKey = next;
                return;
            }
            var previous = _previousKeys.FirstOrDefault(item => item.KeyId == next.KeyId);
            if (previous != null)
            {
                if (previous.PublicKey != next.PublicKey)
                {
                    throw new SwmIntegrityException(
                        0,
                        "online_key_manifest_invalid",
                        "online key id was rebound to different key material",
                        IntegrityFailureAction.DenyOperations);
                }
                _previousKeys.Remove(previous);
            }
            if (_currentKey != null)
            {
                _previousKeys.Add(_currentKey);
                while (_previousKeys.Count > MaximumPreviousKeys)
                {
                    _previousKeys.RemoveAt(0);
                }
            }
            _currentKey = next;
        }
    }

    private string EnsureSession()
    {
        if (!HasValidSession())
        {
            _session = null;
            _sessionExpiresAt = 0;
            throw new SwmSessionException(401, "authz_session_invalid", "authorization session is missing or expired");
        }
        return _session!;
    }

    private Uri BuildUri(string path, string? query)
    {
        var baseUri = _options.BaseUri;
        var builder = new UriBuilder(baseUri)
        {
            Path = path,
            Query = query?.TrimStart('?') ?? string.Empty
        };
        return builder.Uri;
    }

    private Uri BuildWebUri(string path)
    {
        var builder = new UriBuilder(_options.WebBaseUri)
        {
            Path = path,
            Query = string.Empty
        };
        return builder.Uri;
    }

    private static string CreateDebugHmac(
        string secret,
        string method,
        string path,
        ReadOnlySpan<byte> body,
        string timestamp,
        string nonce,
        string clientId)
    {
        var canonical = string.Join(
            "\n",
            method,
            path,
            string.Empty,
            CryptoUtil.Sha256Hex(body),
            timestamp,
            nonce,
            clientId);
        return CryptoUtil.HmacSha256Hex(secret, canonical);
    }

    private static string BuildCanonicalQuery(string query)
    {
        if (string.IsNullOrWhiteSpace(query))
        {
            return string.Empty;
        }
        var pairs = new List<KeyValuePair<string, string>>();
        foreach (var item in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var index = item.IndexOf('=');
            var key = index >= 0 ? item[..index] : item;
            var value = index >= 0 ? item[(index + 1)..] : string.Empty;
            pairs.Add(new KeyValuePair<string, string>(
                Uri.UnescapeDataString(key.Replace("+", "%20")),
                Uri.UnescapeDataString(value.Replace("+", "%20"))));
        }
        pairs.Sort((left, right) =>
        {
            var comparison = string.CompareOrdinal(left.Key, right.Key);
            return comparison != 0 ? comparison : string.CompareOrdinal(left.Value, right.Value);
        });
        return string.Join(
            "&",
            pairs.Select(pair =>
                $"{Uri.EscapeDataString(pair.Key).Replace("+", "%20").Replace("*", "%2A")}=" +
                $"{Uri.EscapeDataString(pair.Value).Replace("+", "%20").Replace("*", "%2A")}"));
    }

    private static async Task<byte[]> ReadBoundedAsync(
        HttpContent content,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        await using var source = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var target = new MemoryStream();
        var buffer = new byte[16 * 1024];
        while (true)
        {
            var read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }
            if (target.Length + read > maximumBytes)
            {
                throw new SwmProtocolException("response body exceeds the accepted limit");
            }
            target.Write(buffer, 0, read);
        }
        return target.ToArray();
    }

    private static bool IsTransientStatus(int status)
    {
        return status is 408 or 429 or 500 or 502 or 503 or 504;
    }

    private static TimeSpan Backoff(RequestPolicy policy, int attempt)
    {
        if (policy.BackoffMilliseconds <= 0)
        {
            return TimeSpan.Zero;
        }
        var scaled = (long)policy.BackoffMilliseconds << Math.Min(attempt, 16);
        return TimeSpan.FromMilliseconds(Math.Min(scaled, Math.Max(policy.BackoffMaxMilliseconds, policy.BackoffMilliseconds)));
    }

    private static bool CanWait(RequestPolicy policy, long started, TimeSpan delay, int attempt)
    {
        if (attempt >= policy.Retries)
        {
            return false;
        }
        if (policy.DeadlineMilliseconds <= 0)
        {
            return true;
        }
        return ElapsedMilliseconds(started) + delay.TotalMilliseconds + policy.TimeoutMilliseconds <=
            policy.DeadlineMilliseconds;
    }

    private static long ElapsedMilliseconds(long startedTimestamp)
    {
        return (long)Stopwatch.GetElapsedTime(startedTimestamp).TotalMilliseconds;
    }

    private static TimeSpan? ParseRetryAfter(ProtocolResponse response)
    {
        if (!response.Headers.TryGetValue("Retry-After", out var values) || values.Length == 0)
        {
            return null;
        }
        if (int.TryParse(values[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds))
        {
            return TimeSpan.FromSeconds(Math.Max(seconds, 0));
        }
        if (DateTimeOffset.TryParse(values[0], CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var date))
        {
            var delay = date - DateTimeOffset.UtcNow;
            return delay > TimeSpan.Zero ? delay : TimeSpan.Zero;
        }
        return null;
    }

    private static bool LooksLikeCode(string value)
    {
        if (value.Length is 0 or > 128)
        {
            return false;
        }
        return value.All(character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '_');
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}
