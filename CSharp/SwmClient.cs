using SwmSdk.Internal;

namespace SwmSdk;

public sealed partial class SwmClient : IAsyncDisposable, IDisposable
{
    private readonly SwmClientOptions _options;
    private readonly RequestPipeline _pipeline;
    private readonly HostIntegrityManager _hostIntegrity;
    private bool _disposed;

    public SwmClient(SwmClientOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        ValidateOptions(options);
        _pipeline = new RequestPipeline(options);
        _hostIntegrity = new HostIntegrityManager(options, _pipeline.StateStore);
        if (_hostIntegrity.ReadCachedPolicy() is { } cachedPolicy)
        {
            _pipeline.SetHostIntegrityPolicy(cachedPolicy);
        }
    }

    public string DeviceId => _pipeline.DeviceId;
    public string InstallId => _pipeline.InstallId;
    public string DeviceKeyId => _pipeline.DeviceKeyId;
    public string KeyThumbprint => _pipeline.KeyThumbprint;
    public string? SessionToken => _pipeline.SessionToken;
    public long SessionExpiresAt => _pipeline.SessionExpiresAt;
    public SwmCloudState CloudState => GetCloudState();

    public async Task RefreshOnlineKeysAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        await _pipeline.RefreshOnlineKeysAsync(force: true, cancellationToken).ConfigureAwait(false);
    }

    public async Task<DeviceKeyRotationResult> RotateDeviceKeyAsync(
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        return await _pipeline.RotateDeviceKeyAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<UpdateCheckResponse> CheckUpdateAsync(
        string? userId = null,
        IReadOnlyDictionary<string, object?>? attributes = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        var evidence = await _hostIntegrity.GetEvidenceAsync(cancellationToken).ConfigureAwait(false);
        string? challenge = null;
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var payload = new UpdateCheckRequest
            {
                ChannelCode = _options.Channel,
                CurrentVersion = _options.Version,
                VersionCode = _options.VersionCode,
                Platform = _options.Platform,
                Arch = _options.Arch,
                DeviceId = DeviceId,
                UserId = string.IsNullOrWhiteSpace(userId) ? null : userId.Trim(),
                Attributes = JsonUtil.ToElementMap(attributes),
                DeviceAuth = _pipeline.CreateDeviceAuth(challenge),
                IntegrityState = evidence?.IntegrityState,
                IntegrityFailureCode = evidence?.IntegrityFailureCode,
                IntegrityEvidenceVersion = evidence?.EvidenceVersion,
                IntegrityManifestSha256 = evidence?.ManifestSha256,
                IntegrityFiles = evidence?.Files
            };
            var request = new ProtocolRequest(
                HttpMethod.Post,
                "/api/client/update-check",
                SwmOperationClass.UpdateCheck,
                JsonUtil.SerializeToUtf8(payload),
                EncryptBody: true,
                RequireSession: false,
                RequireTrustedTime: true,
                RequireOnlineKey: true);
            var response = await _pipeline.SendAsync(request, cancellationToken).ConfigureAwait(false);
            if (response.StatusCode == 428 && attempt == 0)
            {
                var registration = JsonUtil.Deserialize<DeviceRegistrationChallengeResponse>(response.Body);
                if (string.IsNullOrWhiteSpace(registration.Challenge))
                {
                    throw new SwmProtocolException("device registration challenge is missing");
                }
                if (registration.ExpiresAt <= _pipeline.Clock.NowUnixSeconds)
                {
                    throw new SwmProtocolException("device registration challenge has expired");
                }
                challenge = registration.Challenge;
                continue;
            }
            _pipeline.ThrowIfError(response);
            var update = _pipeline.VerifyAuthz<UpdateCheckResponse>(response, response.RequestNonce);
            _pipeline.SetHostIntegrityPolicy(update.HostIntegrityRequired);
            _hostIntegrity.StorePolicy(update.HostIntegrityRequired);
            ArtifactVerifier.VerifyUpdate(
                update,
                _options.AppId,
                _options.Arch,
                _options.RootTrustKeyId,
                _options.RootTrustPublicKey);
            return update;
        }
        throw new SwmProtocolException("device registration challenge retry was exhausted");
    }

    public async Task<HeartbeatResult> ReportHeartbeatAsync(
        string? appVersion = null,
        string? userId = null,
        IReadOnlyDictionary<string, object?>? attributes = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        var evidence = _pipeline.HostIntegrityRequired
            ? await _hostIntegrity.GetRequiredEvidenceAsync(cancellationToken).ConfigureAwait(false)
            : await _hostIntegrity.GetEvidenceAsync(cancellationToken).ConfigureAwait(false);
        if (_pipeline.HostIntegrityRequired && evidence?.IntegrityState != "verified")
        {
            throw new SwmIntegrityException(
                0,
                evidence?.IntegrityFailureCode ?? "host_manifest_missing",
                "host integrity evidence is required for heartbeat",
                _pipeline.LastFailureAction);
        }

        var payload = new HeartbeatRequest
        {
            DeviceId = DeviceId,
            ChannelCode = _options.Channel,
            AppVersion = appVersion ?? _options.Version,
            Platform = _options.Platform,
            Arch = _options.Arch,
            UserId = string.IsNullOrWhiteSpace(userId) ? null : userId.Trim(),
            Attributes = attributes == null ? null : JsonUtil.ToElementMap(attributes),
            IntegrityEvidenceVersion = evidence?.EvidenceVersion,
            IntegrityManifestSha256 = evidence?.ManifestSha256,
            IntegrityFiles = evidence?.Files
        };
        var response = await _pipeline.SendAndVerifyAsync<HeartbeatResponse>(
            new ProtocolRequest(
                HttpMethod.Post,
                "/api/client/heartbeat",
                SwmOperationClass.Heartbeat,
                JsonUtil.SerializeToUtf8(payload),
                EncryptBody: true,
                RequireSession: true,
                RequireTrustedTime: true,
                RequireOnlineKey: true),
            cancellationToken).ConfigureAwait(false);
        return new HeartbeatResult(response.Ok, response.ServerTime, response.Maintenance);
    }

    public Task ReportEventAsync(
        string eventName,
        IReadOnlyDictionary<string, object?>? properties = null,
        CancellationToken cancellationToken = default)
    {
        return ReportEventsAsync(
            [
                new EventIngestItem
                {
                    DeviceId = DeviceId,
                    EventName = eventName,
                    EventTime = DateTimeOffset.UtcNow,
                    ChannelCode = _options.Channel,
                    Properties = JsonUtil.ToElementMap(properties),
                    Attributes = new Dictionary<string, System.Text.Json.JsonElement>()
                }
            ],
            cancellationToken);
    }

    public async Task ReportEventsAsync(
        IEnumerable<EventIngestItem> events,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(events);
        var normalized = new List<EventIngestItem>();
        foreach (var item in events)
        {
            if (string.IsNullOrWhiteSpace(item.EventName))
            {
                throw new SwmValidationException(0, null, "event_name is required");
            }
            normalized.Add(new EventIngestItem
            {
                DeviceId = string.IsNullOrWhiteSpace(item.DeviceId) ? DeviceId : item.DeviceId,
                EventName = item.EventName,
                EventTime = item.EventTime == default ? DateTimeOffset.UtcNow : item.EventTime,
                ChannelCode = string.IsNullOrWhiteSpace(item.ChannelCode) ? _options.Channel : item.ChannelCode,
                Properties = item.Properties,
                Attributes = item.Attributes
            });
        }
        if (normalized.Count == 0)
        {
            return;
        }
        var payload = normalized.Count == 1
            ? JsonUtil.SerializeToUtf8(normalized[0])
            : JsonUtil.SerializeToUtf8(new EventBatchRequest { Events = normalized });
        var response = await _pipeline.SendAsync(
            new ProtocolRequest(
                HttpMethod.Post,
                "/api/client/events",
                SwmOperationClass.Events,
                payload,
                EncryptBody: true,
                RequireSession: true,
                RequireTrustedTime: true,
                RequireOnlineKey: true),
            cancellationToken).ConfigureAwait(false);
        _pipeline.ThrowIfError(response);
        _pipeline.VerifyAuthz<Dictionary<string, System.Text.Json.JsonElement>>(response, response.RequestNonce);
    }

    public async Task<EnrollmentTicketResponse> RequestEnrollmentTicketAsync(
        string audience,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (string.IsNullOrWhiteSpace(audience))
        {
            throw new SwmValidationException(0, null, "enrollment audience is required");
        }
        var payload = new EnrollmentTicketRequest { Audience = audience.Trim().ToLowerInvariant() };
        return await _pipeline.SendAndVerifyAsync<EnrollmentTicketResponse>(
            new ProtocolRequest(
                HttpMethod.Post,
                "/api/client/enrollment-ticket",
                SwmOperationClass.EnrollmentTicket,
                JsonUtil.SerializeToUtf8(payload),
                EncryptBody: true,
                RequireSession: true,
                RequireTrustedTime: true,
                RequireOnlineKey: true),
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<FeedbackResponse> SubmitFeedbackAsync(
        FeedbackRequest request,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(request);
        var multipart = await MultipartBuilder.BuildFeedbackAsync(
            DeviceId,
            _options.Channel,
            _options.Version,
            request,
            cancellationToken).ConfigureAwait(false);
        return await _pipeline.SendAndVerifyAsync<FeedbackResponse>(
            new ProtocolRequest(
                HttpMethod.Post,
                "/api/client/feedback",
                SwmOperationClass.Feedback,
                multipart.Body,
                EncryptBody: true,
                RequireSession: true,
                RequireTrustedTime: true,
                RequireOnlineKey: true,
                ContentType: multipart.ContentType),
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<OperationGrant> AuthorizeOperationAsync(
        OperationAuthorizationRequest request,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(request);
        if (_pipeline.IsOfflineBudgetLocked())
        {
            throw new SwmOfflineBudgetException(
                "offline budget exceeded; restart the client and complete a full bootstrap");
        }
        if (string.IsNullOrWhiteSpace(request.Operation))
        {
            throw new SwmValidationException(0, null, "operation is required");
        }
        if (request.Plan.IsEmpty)
        {
            throw new SwmValidationException(0, null, "operation plan is required");
        }
        if (request.StepCount is 0 or > 100000)
        {
            throw new SwmValidationException(0, null, "step_count must be between 1 and 100000");
        }
        if (string.IsNullOrWhiteSpace(request.ConsumerModule))
        {
            throw new SwmValidationException(0, null, "consumer_module is required");
        }
        var hasHostPath = !string.IsNullOrWhiteSpace(request.HostExecutablePath);
        var hasModulePath = !string.IsNullOrWhiteSpace(request.ConsumerModulePath);
        if (hasHostPath != hasModulePath)
        {
            throw new SwmValidationException(
                0,
                null,
                "HostExecutablePath and ConsumerModulePath must be provided together");
        }
        var hostBound = hasHostPath || _pipeline.HostIntegrityRequired;
        if (hostBound && !hasHostPath)
        {
            throw new SwmValidationException(
                0,
                null,
                "host-bound operation authorization requires HostExecutablePath and ConsumerModulePath");
        }

        var challenge = request.ConsumerChallenge ?? CryptoUtil.RandomBytes(32);
        if (challenge.Length != 32)
        {
            throw new SwmValidationException(0, null, "ConsumerChallenge must contain exactly 32 bytes");
        }
        var planHash = CryptoUtil.Sha256Hex(request.Plan.Span);
        string? manifestSha = null;
        string? hostHash = null;
        string? moduleHash = null;
        if (hostBound)
        {
            var evidence = await _hostIntegrity.GetRequiredEvidenceAsync(cancellationToken).ConfigureAwait(false);
            manifestSha = evidence?.ManifestSha256
                ?? throw new SwmIntegrityException(
                    0,
                    "host_manifest_missing",
                    "host integrity manifest is unavailable",
                    _pipeline.LastFailureAction);
            (hostHash, moduleHash) = await _hostIntegrity.ResolveOperationHashesAsync(
                request,
                cancellationToken).ConfigureAwait(false);
        }

        var payload = new OperationAuthorizationWireRequest
        {
            Schema = hostBound ? "operation_grant_v3_host" : "operation_grant_v3_unbound",
            Operation = request.Operation.Trim(),
            PlanSha256 = planHash,
            StepCount = request.StepCount,
            TotalBytes = request.TotalBytes,
            ConsumerChallenge = Convert.ToHexString(challenge).ToLowerInvariant(),
            IntegrityManifestSha256 = manifestSha,
            HostExeSha256 = hostHash,
            ConsumerModule = request.ConsumerModule.Trim(),
            ConsumerModuleSha256 = moduleHash
        };
        return await _pipeline.SendAndVerifyAsync<OperationGrant>(
            new ProtocolRequest(
                HttpMethod.Post,
                "/api/client/operation-authorizations",
                SwmOperationClass.OperationAuthorization,
                JsonUtil.SerializeToUtf8(payload),
                EncryptBody: true,
                RequireSession: true,
                RequireTrustedTime: true,
                RequireOnlineKey: true),
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<OperationConsumptionReceipt> ConsumeOperationAuthorizationAsync(
        OperationGrant grant,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(grant);
        if (_pipeline.IsOfflineBudgetLocked())
        {
            throw new SwmOfflineBudgetException(
                "offline budget exceeded; restart the client and complete a full bootstrap");
        }
        if (grant.Schema is not ("operation_grant_v3_host" or "operation_grant_v3_unbound") ||
            !Guid.TryParse(grant.GrantId, out _) ||
            string.IsNullOrWhiteSpace(grant.Operation) ||
            string.IsNullOrWhiteSpace(grant.PlanSha256) ||
            string.IsNullOrWhiteSpace(grant.ConsumerModule) ||
            string.IsNullOrWhiteSpace(grant.ConsumerChallenge) ||
            grant.StepCount == 0 ||
            grant.IssuedAt <= 0 ||
            grant.ExpiresAt <= grant.IssuedAt)
        {
            throw new SwmValidationException(0, null, "operation grant is incomplete or invalid");
        }
        var payload = new OperationConsumeWireRequest
        {
            GrantId = grant.GrantId,
            Operation = grant.Operation,
            PlanSha256 = grant.PlanSha256,
            StepCount = grant.StepCount,
            TotalBytes = grant.TotalBytes,
            ConsumerChallenge = grant.ConsumerChallenge,
            IssuedAt = grant.IssuedAt,
            ExpiresAt = grant.ExpiresAt,
            IntegrityManifestSha256 = grant.IntegrityManifestSha256,
            HostExeSha256 = grant.HostExeSha256,
            ConsumerModule = grant.ConsumerModule,
            ConsumerModuleSha256 = grant.ConsumerModuleSha256
        };
        return await _pipeline.SendAndVerifyAsync<OperationConsumptionReceipt>(
            new ProtocolRequest(
                HttpMethod.Post,
                "/api/client/operation-authorizations/consume",
                SwmOperationClass.OperationGrantConsume,
                JsonUtil.SerializeToUtf8(payload),
                EncryptBody: true,
                RequireSession: true,
                RequireTrustedTime: true,
                RequireOnlineKey: true),
            cancellationToken).ConfigureAwait(false);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        _pipeline.Dispose();
    }

    public ValueTask DisposeAsync()
    {
        Dispose();
        return ValueTask.CompletedTask;
    }

    private SwmCloudState GetCloudState()
    {
        if (!_pipeline.Clock.IsInitialized)
        {
            return SwmCloudState.Unavailable;
        }
        if (!_pipeline.HasValidSession())
        {
            return _pipeline.SessionExpiresAt > 0 ? SwmCloudState.Expired : SwmCloudState.Unavailable;
        }
        return SwmCloudState.Available;
    }

    private static void ValidateOptions(SwmClientOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.AppId) ||
            string.IsNullOrWhiteSpace(options.ReleaseId) ||
            string.IsNullOrWhiteSpace(options.Version) ||
            string.IsNullOrWhiteSpace(options.RootTrustKeyId) ||
            string.IsNullOrWhiteSpace(options.RootTrustPublicKey))
        {
            throw new SwmConfigurationException(
                "AppId, ReleaseId, Version, RootTrustKeyId and RootTrustPublicKey are required");
        }
        if (!Guid.TryParse(options.AppId, out _) || !Guid.TryParse(options.ReleaseId, out _))
        {
            throw new SwmConfigurationException("AppId and ReleaseId must be UUID values");
        }
        var baseUri = options.BaseUri;
        if (baseUri.Scheme == Uri.UriSchemeHttp && !options.AllowInsecureHttp)
        {
            throw new SwmConfigurationException("HTTPS is required unless AllowInsecureHttp is enabled");
        }
        CryptoUtil.DecodeKeyMaterial(options.RootTrustPublicKey);
        _ = options.WebBaseUri;
        if (!string.IsNullOrWhiteSpace(options.HostIntegrity.ManifestPath) &&
            Path.IsPathRooted(options.HostIntegrity.ManifestPath))
        {
            throw new SwmConfigurationException("HostIntegrity.ManifestPath must be package-relative");
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}
