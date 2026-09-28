using System.Text;
using System.Text.Json;
using SwmSdk.Internal;

namespace SwmSdk;

public sealed partial class SwmClient
{
    public async Task<JsonElement> ResolveFirmwareIdentityAsync(
        IReadOnlyDictionary<string, object?> metadata,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(metadata);
        var allowed = new HashSet<string>(StringComparer.Ordinal)
        {
            "ota_target_version",
            "version_name",
            "post_build",
            "oplus_rom_version",
            "android_version",
            "post_sdk_level"
        };
        var normalized = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var pair in metadata)
        {
            if (!allowed.Contains(pair.Key) || pair.Value == null)
            {
                continue;
            }
            if (pair.Value is not string text || text.Length > 512)
            {
                throw new SwmValidationException(0, null, $"firmware metadata field is invalid: {pair.Key}");
            }
            normalized[pair.Key] = text;
        }
        if (normalized.Count == 0)
        {
            throw new SwmValidationException(0, null, "firmware metadata must contain at least one supported field");
        }
        var response = await _pipeline.SendFirmwareResolveAsync(
            JsonUtil.SerializeToUtf8(normalized),
            cancellationToken).ConfigureAwait(false);
        _pipeline.ThrowIfError(response);
        using var document = JsonDocument.Parse(response.Body);
        return document.RootElement.Clone();
    }

    public async Task<DebugRequestTicket> CreateDebugRequestAsync(
        string note,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (note.Length is < 2 or > 200)
        {
            throw new SwmValidationException(0, null, "debug note must contain 2 to 200 characters");
        }
        var sessionId = CryptoUtil.Base64UrlEncode(CryptoUtil.RandomBytes(32));
        var enrollment = await RequestEnrollmentTicketAsync("debug", cancellationToken).ConfigureAwait(false);
        var enrollBody = JsonUtil.SerializeToUtf8(new DebugEnrollRequest
        {
            Ticket = enrollment.Ticket,
            AppId = _options.AppId,
            ReleaseId = _options.ReleaseId,
            SessionId = sessionId,
            Pcid = DeviceId,
            AppVersion = _options.Version
        });
        var enrollResponse = await _pipeline.EnrollDebugClientAsync(enrollBody, cancellationToken)
            .ConfigureAwait(false);
        _pipeline.ThrowIfError(enrollResponse);
        var credentials = JsonUtil.Deserialize<DebugEnrollResponse>(enrollResponse.Body);
        if (string.IsNullOrWhiteSpace(credentials.ClientId) ||
            string.IsNullOrWhiteSpace(credentials.ClientSecret) ||
            credentials.ExpiresAt <= _pipeline.Clock.NowUnixSeconds ||
            credentials.ExpiresAt > _pipeline.Clock.NowUnixSeconds + 5 * 60 + 5)
        {
            throw new SwmProtocolException("debug enrollment response is invalid");
        }
        var debugCredentials = new DebugCredentials
        {
            ClientId = credentials.ClientId,
            ClientSecret = credentials.ClientSecret,
            ExpiresAt = credentials.ExpiresAt
        };
        var createBody = JsonUtil.SerializeToUtf8(new DebugCreateRequest
        {
            SessionId = sessionId,
            Pcid = DeviceId,
            AppVersion = _options.Version,
            Note = note
        });
        var createResponse = await _pipeline.CreateDebugRequestAsync(
            debugCredentials,
            createBody,
            cancellationToken).ConfigureAwait(false);
        _pipeline.ThrowIfError(createResponse);
        var created = JsonUtil.Deserialize<DebugCreateResponse>(createResponse.Body);
        if (!Guid.TryParse(created.RequestId, out _) ||
            string.IsNullOrWhiteSpace(created.WatchToken) ||
            created.ExpiresAt <= _pipeline.Clock.NowUnixSeconds ||
            created.ExpiresAt > _pipeline.Clock.NowUnixSeconds + 5 * 60 + 5)
        {
            throw new SwmProtocolException("debug create response is invalid");
        }
        return new DebugRequestTicket
        {
            RequestId = created.RequestId!,
            WatchToken = created.WatchToken,
            ExpiresAt = created.ExpiresAt,
            Credentials = debugCredentials,
            SessionId = sessionId
        };
    }

    public async Task CancelDebugRequestAsync(
        DebugRequestTicket ticket,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(ticket);
        var credentials = ticket.Credentials
            ?? throw new SwmValidationException(0, null, "debug ticket is missing enrollment credentials");
        var response = await _pipeline.CancelDebugRequestAsync(
            credentials,
            ticket.RequestId,
            ticket.WatchToken,
            cancellationToken).ConfigureAwait(false);
        _pipeline.ThrowIfError(response);
    }

    public async IAsyncEnumerable<DebugDecisionEvent> WatchDebugRequestAsync(
        DebugRequestTicket ticket,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(ticket);
        var credentials = ticket.Credentials
            ?? throw new SwmValidationException(0, null, "debug ticket is missing enrollment credentials");
        var expectedSessionHash = CryptoUtil.Sha256Hex(Encoding.UTF8.GetBytes(ticket.SessionId ?? string.Empty));
        var (response, requestNonce) = await _pipeline.OpenDebugEventStreamAsync(
            credentials,
            ticket.RequestId,
            ticket.WatchToken,
            cancellationToken).ConfigureAwait(false);
        using (response)
        {
            if ((int)response.StatusCode is < 200 or >= 300)
            {
                var body = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
                _pipeline.ThrowIfError(new ProtocolResponse(
                    (int)response.StatusCode,
                    body,
                    requestNonce,
                    response.Headers.ToDictionary(
                        pair => pair.Key,
                        pair => pair.Value.ToArray(),
                        StringComparer.OrdinalIgnoreCase)));
            }
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: false);
            var eventName = string.Empty;
            var data = new StringBuilder();
            while (!cancellationToken.IsCancellationRequested)
            {
                var line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
                if (line == null)
                {
                    yield break;
                }
                if (line.Length == 0)
                {
                    if (data.Length > 0 &&
                        (eventName == "debug-request-state" || eventName == "debug_request_state"))
                    {
                        var decision = DecodeDebugDecision(
                            requestNonce,
                            ticket.RequestId,
                            expectedSessionHash,
                            Encoding.UTF8.GetBytes(data.ToString()));
                        yield return decision;
                        if (decision.State is "approved" or "rejected" or "cancelled")
                        {
                            yield break;
                        }
                    }
                    eventName = string.Empty;
                    data.Clear();
                    continue;
                }
                if (line.StartsWith("event:", StringComparison.OrdinalIgnoreCase))
                {
                    eventName = line[6..].Trim();
                }
                else if (line.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
                {
                    if (data.Length > 0)
                    {
                        data.Append('\n');
                    }
                    data.Append(line[5..].Trim());
                }
            }
        }
    }

    private DebugDecisionEvent DecodeDebugDecision(
        string requestNonce,
        string expectedRequestId,
        string expectedSessionHash,
        byte[] carrier)
    {
        var payload = _pipeline.VerifyAuthz<JsonElement>(
            new ProtocolResponse(
                200,
                carrier,
                requestNonce,
                new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)),
            requestNonce);
        if (!payload.TryGetProperty("version", out var versionNode) ||
            !payload.TryGetProperty("request_id", out var requestNode) ||
            !payload.TryGetProperty("session_id_hash", out var sessionNode) ||
            !payload.TryGetProperty("status", out var stateNode) ||
            !payload.TryGetProperty("expires_at", out var expiresNode))
        {
            throw new SwmProtocolException("debug decision payload is incomplete");
        }
        var version = versionNode.GetString();
        var requestId = requestNode.GetString();
        var sessionHash = sessionNode.GetString();
        var state = stateNode.GetString();
        var reason = payload.TryGetProperty("reason", out var reasonNode) ? reasonNode.GetString() : null;
        var expiresAt = expiresNode.GetInt64();
        if (version != "debug_decision_v1" ||
            requestId != expectedRequestId ||
            !string.Equals(sessionHash, expectedSessionHash, StringComparison.OrdinalIgnoreCase) ||
            state is not ("pending" or "approved" or "rejected" or "cancelled") ||
            expiresAt <= 0)
        {
            throw new SwmProtocolException("debug decision payload is invalid");
        }
        return new DebugDecisionEvent
        {
            State = state,
            Reason = reason,
            AuthorizationExpiresAt = state == "approved" ? expiresAt : 0
        };
    }
}
