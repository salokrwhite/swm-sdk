package com.swm.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.swm.sdk.HttpTransport;
import com.swm.sdk.internal.CryptoUtil;
import com.swm.sdk.internal.HostIntegrity;
import com.swm.sdk.internal.JsonUtil;
import com.swm.sdk.internal.Multipart;
import com.swm.sdk.internal.RequestPipeline;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Windows desktop client for the SWM runtime protocol.
 */
public final class SwmClient implements AutoCloseable {
    private final SwmClientOptions options;
    private final RequestPipeline pipeline;
    private final HostIntegrity hostIntegrity;
    private final ExecutorService executor;
    private final Map<String, JsonNode> debugCredentials = new ConcurrentHashMap<>();
    private volatile boolean closed;

    public SwmClient(SwmClientOptions options) {
        this.options = Objects.requireNonNull(options, "options");
        validateOptions(options);
        this.pipeline = new RequestPipeline(options, options.httpTransport());
        this.hostIntegrity = new HostIntegrity(options, new com.swm.sdk.internal.StateStore(
            options.appId(), options.storageDirectory()));
        this.executor = Executors.newCachedThreadPool(runnable -> {
            var thread = new Thread(runnable, "swm-sdk-async");
            thread.setDaemon(true);
            return thread;
        });
    }

    public String deviceId() {
        return pipeline.deviceId();
    }

    public String installId() {
        return pipeline.installId();
    }

    public String deviceKeyId() {
        return pipeline.deviceKeyId();
    }

    public void refreshOnlineKeys() {
        checkOpen();
        pipeline.refreshOnlineKeys(true);
    }

    public CompletableFuture<Void> refreshOnlineKeysAsync() {
        return async(() -> {
            refreshOnlineKeys();
            return null;
        });
    }

    public SwmModels.UpdateInfo checkUpdate() {
        return checkUpdate(null, null);
    }

    public SwmModels.UpdateInfo checkUpdate(JsonNode attributes, String userId) {
        checkOpen();
        var payload = JsonUtil.object();
        payload.put("channel_code", options.channel());
        payload.put("current_version", options.version());
        if (options.versionCode() != null) {
            payload.put("version_code", options.versionCode());
        }
        payload.put("platform", options.platform());
        payload.put("arch", options.arch());
        payload.put("device_id", deviceId());
        payload.set("attributes", attributes == null ? JsonUtil.object() : attributes);
        payload.set("device_auth", pipeline.createDeviceAuth(""));
        if (userId != null && !userId.isBlank()) {
            payload.put("user_id", userId.trim());
        }
        addIntegrityEvidence(payload, hostIntegrity.evidence());

        String challenge = "";
        for (int attempt = 0; attempt < 2; attempt++) {
            var response = pipeline.send(new RequestPipeline.Request(
                "POST", "/api/client/update-check", RequestPipeline.Operation.UPDATE_CHECK,
                JsonUtil.bytes(payload), true, false, true, true,
                "application/json; charset=utf-8", "", ""));
            if (response.statusCode() == 428 && attempt == 0) {
                var body = JsonUtil.parse(response.body(), "device registration challenge");
                challenge = JsonUtil.text(body, "challenge");
                var expiresAt = JsonUtil.longValue(body, "expires_at", 0);
                if (challenge.isBlank() || expiresAt <= pipeline.clock().nowUnixSeconds()) {
                    throw new SwmException.Protocol("device registration challenge is invalid");
                }
                payload.set("device_auth", pipeline.createDeviceAuth(challenge));
                continue;
            }
            var data = pipeline.verifyAuthz(response);
            var update = updateFromJson(data);
            pipeline.setHostIntegrityRequired(update.hostIntegrityRequired());
            verifyArtifactManifest(update);
            return update;
        }
        throw new SwmException.Protocol("device registration challenge retry was exhausted");
    }

    public CompletableFuture<SwmModels.UpdateInfo> checkUpdateAsync(
        JsonNode attributes, String userId) {
        return async(() -> checkUpdate(attributes, userId));
    }

    public SwmModels.HeartbeatResult reportHeartbeat() {
        return reportHeartbeat(null, null, null);
    }

    public SwmModels.HeartbeatResult reportHeartbeat(
        String appVersion, JsonNode attributes, String userId) {
        checkOpen();
        var payload = JsonUtil.object();
        payload.put("device_id", deviceId());
        payload.put("channel_code", options.channel());
        payload.put("app_version", appVersion == null || appVersion.isBlank()
            ? options.version() : appVersion);
        payload.put("platform", options.platform());
        payload.put("arch", options.arch());
        payload.set("attributes", attributes == null ? JsonUtil.object() : attributes);
        if (userId != null && !userId.isBlank()) {
            payload.put("user_id", userId.trim());
        }
        var evidence = pipeline.hostIntegrityRequired()
            ? hostIntegrity.requiredEvidence() : hostIntegrity.evidence();
        addIntegrityEvidence(payload, evidence);
        var data = pipeline.sendAndVerify(new RequestPipeline.Request(
            "POST", "/api/client/heartbeat", RequestPipeline.Operation.HEARTBEAT,
            JsonUtil.bytes(payload), true, true, true, true,
            "application/json; charset=utf-8", "", ""));
        var ok = JsonUtil.boolValue(data, "ok", false);
        var serverTime = JsonUtil.text(data, "server_time", false);
        if (!ok || serverTime.isBlank()) {
            throw new SwmException.Protocol("heartbeat response is incomplete or invalid");
        }
        return new SwmModels.HeartbeatResult(true, serverTime,
            maintenanceFromJson(data.get("maintenance")));
    }

    public CompletableFuture<SwmModels.HeartbeatResult> reportHeartbeatAsync(
        String appVersion, JsonNode attributes, String userId) {
        return async(() -> reportHeartbeat(appVersion, attributes, userId));
    }

    public void reportEvent(SwmModels.Event event) {
        reportEvents(List.of(Objects.requireNonNull(event, "event")));
    }

    public void reportEvents(List<SwmModels.Event> events) {
        checkOpen();
        if (events == null || events.isEmpty()) {
            return;
        }
        ObjectNode payload;
        if (events.size() == 1) {
            payload = eventToJson(events.get(0));
        } else {
            payload = JsonUtil.object();
            var array = payload.putArray("events");
            events.forEach(event -> array.add(eventToJson(event)));
        }
        pipeline.sendAndVerify(new RequestPipeline.Request(
            "POST", "/api/client/events", RequestPipeline.Operation.EVENT,
            JsonUtil.bytes(payload), true, true, true, true,
            "application/json; charset=utf-8", "", ""));
    }

    public CompletableFuture<Void> reportEventAsync(SwmModels.Event event) {
        return async(() -> {
            reportEvent(event);
            return null;
        });
    }

    public CompletableFuture<Void> reportEventsAsync(List<SwmModels.Event> events) {
        return async(() -> {
            reportEvents(events);
            return null;
        });
    }

    public SwmModels.FeedbackResult submitFeedback(SwmModels.FeedbackRequest request) {
        checkOpen();
        var payload = Multipart.feedback(deviceId(), options.channel(), options.version(),
            Objects.requireNonNull(request, "request"));
        var data = pipeline.sendAndVerify(new RequestPipeline.Request(
            "POST", "/api/client/feedback", RequestPipeline.Operation.FEEDBACK,
            payload.body(), true, true, true, true, payload.contentType(), "", ""));
        if (!JsonUtil.boolValue(data, "ok", false) || !validUuid(JsonUtil.text(data, "id"))) {
            throw new SwmException.Protocol("feedback response is incomplete or invalid");
        }
        return new SwmModels.FeedbackResult(true, JsonUtil.text(data, "id"));
    }

    public CompletableFuture<SwmModels.FeedbackResult> submitFeedbackAsync(
        SwmModels.FeedbackRequest request) {
        return async(() -> submitFeedback(request));
    }

    public SwmModels.EnrollmentTicket requestEnrollmentTicket(String audience) {
        checkOpen();
        var normalized = audience == null ? "" : audience.trim().toLowerCase(Locale.ROOT);
        if (normalized.isBlank()) {
            throw new SwmException.Configuration("enrollment audience is required");
        }
        var payload = JsonUtil.object().put("audience", normalized);
        var data = pipeline.sendAndVerify(new RequestPipeline.Request(
            "POST", "/api/client/enrollment-ticket", RequestPipeline.Operation.ENROLLMENT,
            JsonUtil.bytes(payload), true, true, true, true,
            "application/json; charset=utf-8", "", ""));
        var ticket = JsonUtil.text(data, "ticket");
        var expiresAt = JsonUtil.longValue(data, "expires_at", 0);
        var responseAudience = JsonUtil.text(data, "audience");
        if (ticket.isBlank() || expiresAt <= pipeline.clock().nowUnixSeconds()
            || !normalized.equalsIgnoreCase(responseAudience)) {
            throw new SwmException.Protocol("enrollment ticket response is incomplete or invalid");
        }
        return new SwmModels.EnrollmentTicket(ticket, expiresAt, responseAudience);
    }

    public CompletableFuture<SwmModels.EnrollmentTicket> requestEnrollmentTicketAsync(
        String audience) {
        return async(() -> requestEnrollmentTicket(audience));
    }

    public SwmModels.DeviceKeyRotationResult rotateDeviceKey() {
        checkOpen();
        return pipeline.rotateDeviceKey();
    }

    public CompletableFuture<SwmModels.DeviceKeyRotationResult> rotateDeviceKeyAsync() {
        return async(this::rotateDeviceKey);
    }

    public SwmModels.OperationGrant authorizeOperation(
        SwmModels.OperationAuthorizationRequest request) {
        checkOpen();
        if (pipeline.offlineLocked()) {
            throw new SwmException.OfflineBudget(
                "offline budget exceeded; restart the client and complete a full bootstrap");
        }
        var hostBound = validateOperationRequest(request);
        byte[] challenge = request.consumerChallenge();
        if (challenge == null || challenge.length == 0) {
            challenge = CryptoUtil.randomBytes(32);
        }
        if (challenge.length != 32) {
            throw new SwmException.Validation("consumer challenge must contain 32 bytes");
        }
        String manifestHash = null;
        String hostHash = null;
        String moduleHash = null;
        if (hostBound) {
            try {
                var hashes = hostIntegrity.resolveOperationHashes(request);
                manifestHash = hostIntegrity.manifestSha256();
                hostHash = hashes[0];
                moduleHash = hashes[1];
            } catch (SwmException exception) {
                throw exception;
            }
        }
        var payload = JsonUtil.object();
        payload.put("schema", hostBound ? "operation_grant_v3_host" : "operation_grant_v3_unbound");
        payload.put("operation", request.operation().trim());
        payload.put("plan_sha256", CryptoUtil.sha256Hex(request.plan()));
        payload.put("step_count", request.stepCount());
        payload.put("total_bytes", request.totalBytes());
        payload.put("consumer_challenge", CryptoUtil.hex(challenge));
        payload.put("consumer_module", request.consumerModule().trim());
        if (hostBound) {
            payload.put("integrity_manifest_sha256", manifestHash);
            payload.put("host_exe_sha256", hostHash);
            payload.put("consumer_module_sha256", moduleHash);
        }
        var data = pipeline.sendAndVerify(new RequestPipeline.Request(
            "POST", "/api/client/operation-authorizations",
            RequestPipeline.Operation.AUTHORIZE, JsonUtil.bytes(payload), true, true, true,
            true, "application/json; charset=utf-8", "", ""));
        return grantFromJson(data, challenge);
    }

    public CompletableFuture<SwmModels.OperationGrant> authorizeOperationAsync(
        SwmModels.OperationAuthorizationRequest request) {
        return async(() -> authorizeOperation(request));
    }

    public SwmModels.OperationConsumptionReceipt consumeOperationAuthorization(
        SwmModels.OperationGrant grant) {
        checkOpen();
        if (pipeline.offlineLocked()) {
            throw new SwmException.OfflineBudget(
                "offline budget exceeded; restart the client and complete a full bootstrap");
        }
        validateGrant(grant);
        var payload = JsonUtil.object();
        payload.put("schema", "operation_grant_consume_v2");
        payload.put("grant_id", grant.grantId());
        payload.put("operation", grant.operation());
        payload.put("plan_sha256", grant.planSha256());
        payload.put("step_count", grant.stepCount());
        payload.put("total_bytes", grant.totalBytes());
        payload.put("consumer_challenge", grant.consumerChallenge());
        payload.put("issued_at", grant.issuedAt());
        payload.put("expires_at", grant.expiresAt());
        payload.put("consumer_module", grant.consumerModule());
        putIfPresent(payload, "integrity_manifest_sha256", grant.integrityManifestSha256());
        putIfPresent(payload, "host_exe_sha256", grant.hostExeSha256());
        putIfPresent(payload, "consumer_module_sha256", grant.consumerModuleSha256());
        var data = pipeline.sendAndVerify(new RequestPipeline.Request(
            "POST", "/api/client/operation-authorizations/consume",
            RequestPipeline.Operation.CONSUME, JsonUtil.bytes(payload), true, true, true,
            true, "application/json; charset=utf-8", "", ""));
        return receiptFromJson(data);
    }

    public CompletableFuture<SwmModels.OperationConsumptionReceipt>
    consumeOperationAuthorizationAsync(SwmModels.OperationGrant grant) {
        return async(() -> consumeOperationAuthorization(grant));
    }

    public void downloadUpdate(SwmModels.UpdateInfo update, Path destination,
                               ProgressListener progress) {
        checkOpen();
        if (update == null || !update.updateAvailable() || update.openInBrowser()
            || !validDownloadUrl(update.downloadUrl())) {
            throw new SwmException.Configuration("update does not contain a valid download URL");
        }
        verifyArtifactManifest(update);
        try {
            if (destination.getParent() != null) {
                Files.createDirectories(destination.getParent());
            }
            var partial = destination.resolveSibling(destination.getFileName() + ".part");
            var existing = Files.isRegularFile(partial) ? Files.size(partial) : 0L;
            var url = update.downloadUrl();
            var authenticated = true;
            HttpTransport.StreamResponse stream = null;
            try {
                for (int redirect = 0; redirect < 4; redirect++) {
                    stream = pipeline.openDownloadStream(url, existing, authenticated);
                    if (stream.statusCode() < 300 || stream.statusCode() >= 400) {
                        break;
                    }
                    var location = firstHeader(stream.headers(), "location");
                    if (location == null || location.isBlank()) {
                        throw new SwmException.Protocol("download redirect is missing Location");
                    }
                    url = resolveRedirect(url, location);
                    authenticated = false;
                }
                if (stream == null || stream.statusCode() >= 300 && stream.statusCode() < 400) {
                    throw new SwmException.Protocol("download redirect limit exceeded");
                }
                if (stream.statusCode() >= 400) {
                    var body = stream.body().readAllBytes();
                    throw new SwmException(SwmException.Kind.API, stream.statusCode(), "",
                        new String(body, StandardCharsets.UTF_8));
                }
                var contentRange = firstHeader(stream.headers(), "content-range");
                var append = existing > 0 && stream.statusCode() == 206;
                long expected = contentRange == null ? 0 : parseTotal(contentRange);
                if (!append) {
                    existing = 0;
                }
                try (var output = Files.newOutputStream(partial,
                    append ? StandardOpenOption.APPEND : StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.CREATE)) {
                    var buffer = new byte[128 * 1024];
                    long written = existing;
                    int read;
                    while ((read = stream.body().read(buffer)) >= 0) {
                        output.write(buffer, 0, read);
                        written += read;
                        if (progress != null) {
                            progress.onProgress(written, expected);
                        }
                    }
                    output.flush();
                    if (expected > 0 && written != expected) {
                        Files.deleteIfExists(partial);
                        throw new SwmException.Protocol("download length mismatch");
                    }
                    try {
                        verifyDownload(update, partial);
                    } catch (RuntimeException exception) {
                        Files.deleteIfExists(partial);
                        throw exception;
                    }
                    Files.move(partial, destination, StandardCopyOption.REPLACE_EXISTING);
                }
            } finally {
                if (stream != null) {
                    stream.close();
                }
            }
        } catch (IOException exception) {
            throw new SwmException.Network("download failed", exception);
        }
    }

    public CompletableFuture<Void> downloadUpdateAsync(
        SwmModels.UpdateInfo update, Path destination, ProgressListener progress) {
        return async(() -> {
            downloadUpdate(update, destination, progress);
            return null;
        });
    }

    public UpdateStream watchUpdates(
        SwmModels.UpdateStreamOptions streamOptions,
        UpdateStream.EventListener onEvent,
        UpdateStream.ErrorListener onError,
        UpdateStream.ControlListener onControl
    ) {
        checkOpen();
        var settings = streamOptions == null ? SwmModels.UpdateStreamOptions.defaults() : streamOptions;
        return new UpdateStream(handle -> {
            int attempt = 0;
            while (handle.running()) {
                try {
                    var currentVersion = settings.currentVersion() == null
                        ? options.version() : settings.currentVersion();
                    var versionCode = settings.versionCode() == null
                        ? options.versionCode() : settings.versionCode();
                    var query = "device_id=" + urlEncode(deviceId())
                        + "&channel_code=" + urlEncode(options.channel())
                        + "&platform=" + urlEncode(options.platform())
                        + "&arch=" + urlEncode(options.arch())
                        + "&current_version=" + urlEncode(currentVersion)
                        + "&version_code=" + (versionCode == null ? 0 : versionCode);
                    var url = options.baseUri().resolve(
                        "api/client/updates/stream?" + query).toString();
                    var nonce = new String[1];
                    try (var stream = pipeline.openUpdateStream(url, nonce)) {
                        handle.attach(stream);
                        if (stream.statusCode() < 200 || stream.statusCode() >= 300) {
                            throw new SwmException.Network("update stream was rejected", null);
                        }
                        attempt = 0;
                        var reader = new BufferedReader(new InputStreamReader(
                            stream.body(), StandardCharsets.UTF_8));
                        var event = new SseEvent();
                        boolean verified = false;
                        String line;
                        while (handle.running() && (line = reader.readLine()) != null) {
                            if (line.startsWith(":")) {
                                continue;
                            }
                            if (line.isEmpty()) {
                                if (event.data.length() > 0 && !event.name.isBlank()) {
                                    if ("authz".equals(event.name)) {
                                        pipeline.verifyAuthz(new RequestPipeline.Response(
                                            200, event.data.toString().getBytes(StandardCharsets.UTF_8),
                                            nonce[0],
                                            Map.of()));
                                        verified = true;
                                    } else if ("authz_expired".equals(event.name)) {
                                        throw new SwmException.Session(401, "authz_session_expired",
                                            "update stream authorization expired");
                                    } else if (verified && !"connected".equals(event.name)) {
                                        var response = new RequestPipeline.Response(200,
                                            event.data.toString().getBytes(StandardCharsets.UTF_8),
                                            nonce[0], Map.of());
                                        var data = pipeline.verifyAuthz(response);
                                        var update = eventFromJson(data, event);
                                        if (onControl != null && (update.eventType().equals(
                                            "device_shutdown") || update.eventType().equals(
                                            "maintenance_scheduled") || update.eventType().equals(
                                            "maintenance_cancelled"))) {
                                            onControl.onControl(update);
                                        }
                                        if (onEvent != null) {
                                            onEvent.onEvent(update);
                                        }
                                    }
                                }
                                event = new SseEvent();
                                continue;
                            }
                            if (line.startsWith("event:")) {
                                event.name = line.substring(6).trim();
                            } else if (line.startsWith("id:")) {
                                event.id = line.substring(3).trim();
                            } else if (line.startsWith("data:")) {
                                if (event.data.length() > 0) {
                                    event.data.append('\n');
                                }
                                event.data.append(line.substring(5).trim());
                            }
                        }
                    }
                } catch (SwmException exception) {
                    if (onError != null) {
                        onError.onError(exception);
                    }
                    if (!settings.reconnect() || !handle.running()
                        || exception.kind() == SwmException.Kind.SESSION
                        || exception.kind() == SwmException.Kind.UNAUTHORIZED
                        || exception.kind() == SwmException.Kind.INTEGRITY
                        || exception.kind() == SwmException.Kind.DEVICE_BLOCKED) {
                        return;
                    }
                    var delay = backoff(settings, attempt++);
                    try {
                        Thread.sleep(delay);
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                } catch (IOException exception) {
                    if (onError != null) {
                        onError.onError(new SwmException.Network("update stream failed", exception));
                    }
                    return;
                }
            }
        });
    }

    public JsonNode resolveFirmwareIdentity(JsonNode metadata) {
        checkOpen();
        if (metadata == null || !metadata.isObject()) {
            throw new SwmException.Validation("firmware metadata must be an object");
        }
        var allowed = List.of("ota_target_version", "version_name", "post_build",
            "oplus_rom_version", "android_version", "post_sdk_level");
        var normalized = JsonUtil.object();
        metadata.fields().forEachRemaining(entry -> {
            if (!allowed.contains(entry.getKey())) {
                return;
            }
            if (!entry.getValue().isTextual() || entry.getValue().asText().length() > 512) {
                throw new SwmException.Validation(
                    "firmware metadata field is invalid: " + entry.getKey());
            }
            normalized.set(entry.getKey(), entry.getValue());
        });
        if (normalized.isEmpty()) {
            throw new SwmException.Validation("firmware metadata has no supported fields");
        }
        var response = pipeline.sendWeb("POST", "/api/v1/device-models/resolve",
            JsonUtil.bytes(normalized), RequestPipeline.Operation.FIRMWARE, true,
            null, null, null);
        pipeline.throwIfError(response);
        return JsonUtil.parse(response.body(), "firmware identity response");
    }

    public CompletableFuture<JsonNode> resolveFirmwareIdentityAsync(JsonNode metadata) {
        return async(() -> resolveFirmwareIdentity(metadata));
    }

    public SwmModels.DebugRequestTicket createDebugRequest(String note) {
        checkOpen();
        if (note == null || note.length() < 2 || note.length() > 200) {
            throw new SwmException.Validation("debug note must contain 2 to 200 characters");
        }
        var enrollment = requestEnrollmentTicket("debug");
        var sessionId = CryptoUtil.base64Url(CryptoUtil.randomBytes(32));
        var enroll = JsonUtil.object();
        enroll.put("ticket", enrollment.ticket());
        enroll.put("app_id", options.appId());
        enroll.put("release_id", options.releaseId());
        enroll.put("session_id", sessionId);
        enroll.put("pcid", deviceId());
        enroll.put("app_version", options.version());
        var enrollResponse = pipeline.sendWeb("POST", "/api/v1/client/debug-enroll",
            JsonUtil.bytes(enroll), RequestPipeline.Operation.DEBUG, false, null, null, null);
        pipeline.throwIfError(enrollResponse);
        var credentials = JsonUtil.parse(enrollResponse.body(), "debug enrollment");
        var clientId = JsonUtil.text(credentials, "client_id");
        var clientSecret = JsonUtil.text(credentials, "client_secret");
        var credentialsExpiresAt = JsonUtil.longValue(credentials, "expires_at", 0);
        var now = pipeline.clock().nowUnixSeconds();
        if (clientId.isBlank() || clientSecret.isBlank() || credentialsExpiresAt <= now
            || credentialsExpiresAt > now + 305) {
            throw new SwmException.Protocol("debug enrollment response is invalid");
        }
        var create = JsonUtil.object();
        create.put("session_id", sessionId);
        create.put("pcid", deviceId());
        create.put("app_version", options.version());
        create.put("note", note);
        var createResponse = pipeline.sendWeb("POST", "/api/v1/client/debug-requests",
            JsonUtil.bytes(create), RequestPipeline.Operation.DEBUG, true,
            credentials, null, null);
        pipeline.throwIfError(createResponse);
        var created = JsonUtil.parse(createResponse.body(), "debug create");
        var requestId = JsonUtil.text(created, "request_id");
        var watchToken = JsonUtil.text(created, "watch_token");
        var expiresAt = JsonUtil.longValue(created, "expires_at", 0);
        if (!validUuid(requestId) || watchToken.isBlank() || expiresAt <= now
            || expiresAt > now + 305) {
            throw new SwmException.Protocol("debug create response is invalid");
        }
        var ticket = new SwmModels.DebugRequestTicket(requestId, watchToken, expiresAt);
        debugCredentials.put(ticket.requestId(), credentials);
        return ticket;
    }

    public CompletableFuture<SwmModels.DebugRequestTicket> createDebugRequestAsync(String note) {
        return async(() -> createDebugRequest(note));
    }

    public void cancelDebugRequest(SwmModels.DebugRequestTicket ticket) {
        checkOpen();
        if (ticket == null || ticket.requestId().isBlank() || ticket.watchToken().isBlank()) {
            throw new SwmException.Validation("debug ticket is invalid");
        }
        var credentials = debugCredentials.get(ticket.requestId());
        if (credentials == null) {
            throw new SwmException.Validation("debug request credentials are unavailable");
        }
        var response = pipeline.sendWeb("POST",
            "/api/v1/client/debug-requests/" + ticket.requestId() + "/cancel",
            new byte[0], RequestPipeline.Operation.DEBUG, true, credentials,
            ticket.watchToken(), ticket.requestId());
        pipeline.throwIfError(response);
        debugCredentials.remove(ticket.requestId());
    }

    public CompletableFuture<Void> cancelDebugRequestAsync(SwmModels.DebugRequestTicket ticket) {
        return async(() -> {
            cancelDebugRequest(ticket);
            return null;
        });
    }

    public UpdateStream watchDebugRequest(
        SwmModels.DebugRequestTicket ticket,
        java.util.function.Consumer<SwmModels.DebugDecisionEvent> onDecision,
        UpdateStream.ErrorListener onError
    ) {
        checkOpen();
        var credentials = debugCredentials.get(ticket.requestId());
        if (credentials == null) {
            throw new SwmException.Validation("debug request credentials are unavailable");
        }
        return new UpdateStream(handle -> {
            try {
                var nonce = new String[1];
                var path = "/api/v1/client/debug-requests/" + ticket.requestId() + "/events";
                try (var stream = pipeline.openWebStream(path, ticket.requestId(), credentials,
                    ticket.watchToken(), nonce)) {
                    handle.attach(stream);
                    if (stream.statusCode() < 200 || stream.statusCode() >= 300) {
                        throw new SwmException.Network("debug stream was rejected", null);
                    }
                    var reader = new BufferedReader(new InputStreamReader(
                        stream.body(), StandardCharsets.UTF_8));
                    var event = new SseEvent();
                    String line;
                    while (handle.running() && (line = reader.readLine()) != null) {
                        if (line.isEmpty()) {
                            if (event.data.length() > 0
                                && (event.name.equals("debug-request-state")
                                    || event.name.equals("debug_request_state"))) {
                                var response = new RequestPipeline.Response(200,
                                    event.data.toString().getBytes(StandardCharsets.UTF_8),
                                    nonce[0], Map.of());
                                var data = pipeline.verifyAuthz(response);
                                var version = JsonUtil.text(data, "version");
                                var requestId = JsonUtil.text(data, "request_id");
                                var sessionHash = JsonUtil.text(data, "session_id_hash");
                                var status = JsonUtil.text(data, "status");
                                var reason = JsonUtil.text(data, "reason", false);
                                var expires = JsonUtil.longValue(data, "expires_at", 0);
                                var expectedHash = CryptoUtil.sha256Hex(
                                    JsonUtil.text(credentials, "session_id")
                                        .getBytes(StandardCharsets.UTF_8));
                                if (!"debug_decision_v1".equals(version)
                                    || !ticket.requestId().equals(requestId)
                                    || !expectedHash.equalsIgnoreCase(sessionHash)
                                    || !(status.equals("pending") || status.equals("approved")
                                        || status.equals("rejected") || status.equals("cancelled"))
                                    || expires <= 0) {
                                    throw new SwmException.Protocol(
                                        "debug decision payload is invalid");
                                }
                                if (onDecision != null) {
                                    onDecision.accept(new SwmModels.DebugDecisionEvent(status,
                                        reason, status.equals("approved") ? expires : 0));
                                }
                                if (status.equals("approved") || status.equals("rejected")
                                    || status.equals("cancelled")) {
                                    debugCredentials.remove(ticket.requestId());
                                    handle.stop();
                                    return;
                                }
                            }
                            event = new SseEvent();
                            continue;
                        }
                        if (line.startsWith("event:")) {
                            event.name = line.substring(6).trim();
                        } else if (line.startsWith("data:")) {
                            if (event.data.length() > 0) {
                                event.data.append('\n');
                            }
                            event.data.append(line.substring(5).trim());
                        }
                    }
                }
            } catch (SwmException exception) {
                if (onError != null) {
                    onError.onError(exception);
                }
            } catch (IOException exception) {
                if (onError != null) {
                    onError.onError(new SwmException.Network("debug stream failed", exception));
                }
            }
        });
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        executor.shutdownNow();
        pipeline.close();
    }

    private void checkOpen() {
        if (closed) {
            throw new IllegalStateException("SwmClient is closed");
        }
    }

    private <T> CompletableFuture<T> async(java.util.function.Supplier<T> supplier) {
        return CompletableFuture.supplyAsync(supplier, executor);
    }

    private static void addIntegrityEvidence(ObjectNode payload,
                                              SwmModels.IntegrityEvidence evidence) {
        if (evidence == null) {
            return;
        }
        if (evidence.state() != null && !evidence.state().isBlank()) {
            payload.put("integrity_state", evidence.state());
        }
        if (evidence.failureCode() != null && !evidence.failureCode().isBlank()) {
            payload.put("integrity_failure_code", evidence.failureCode());
        }
        if (evidence.evidenceVersion() != null) {
            payload.put("integrity_evidence_version", evidence.evidenceVersion());
        }
        if (evidence.manifestSha256() != null && !evidence.manifestSha256().isBlank()) {
            payload.put("integrity_manifest_sha256", evidence.manifestSha256());
        }
        if (evidence.files() != null && !evidence.files().isEmpty()) {
            var files = payload.putObject("integrity_files");
            evidence.files().forEach(files::put);
        }
    }

    private ObjectNode eventToJson(SwmModels.Event event) {
        if (event == null || event.eventName() == null || event.eventName().isBlank()) {
            throw new SwmException.Validation("event_name is required");
        }
        var value = JsonUtil.object();
        value.put("device_id", event.deviceId() == null || event.deviceId().isBlank()
            ? deviceId() : event.deviceId());
        value.put("event_name", event.eventName());
        value.put("event_time", event.eventTime() == null || event.eventTime().isBlank()
            ? java.time.Instant.now().toString() : event.eventTime());
        value.put("channel_code", event.channelCode() == null || event.channelCode().isBlank()
            ? options.channel() : event.channelCode());
        value.set("properties", event.properties() == null ? JsonUtil.object() : event.properties());
        value.set("attributes", event.attributes() == null ? JsonUtil.object() : event.attributes());
        return value;
    }

    private static SwmModels.MaintenanceInfo maintenanceFromJson(JsonNode value) {
        if (value == null || !value.isObject()) {
            return null;
        }
        return new SwmModels.MaintenanceInfo(
            JsonUtil.boolValue(value, "enabled", false),
            JsonUtil.text(value, "start_at", false),
            JsonUtil.text(value, "message", false),
            JsonUtil.boolValue(value, "active", false));
    }

    private static SwmModels.UpdateInfo updateFromJson(JsonNode value) {
        return new SwmModels.UpdateInfo(
            JsonUtil.boolValue(value, "update_available", false),
            JsonUtil.boolValue(value, "mandatory", false),
            JsonUtil.intValue(value, "heartbeat_interval_seconds", 0),
            JsonUtil.boolValue(value, "open_in_browser", false),
            JsonUtil.text(value, "delivery_method", false),
            JsonUtil.text(value, "release_id", false),
            JsonUtil.text(value, "version", false),
            value.hasNonNull("version_code") ? value.get("version_code").intValue() : null,
            JsonUtil.text(value, "notes", false),
            JsonUtil.text(value, "download_url", false),
            JsonUtil.text(value, "checksum_sha256", false),
            JsonUtil.text(value, "signature", false),
            JsonUtil.text(value, "manifest_key_id", false),
            JsonUtil.text(value, "manifest_public_key", false),
            JsonUtil.text(value, "root_trust_key_id", false),
            JsonUtil.text(value, "root_trust_signature", false),
            JsonUtil.text(value, "artifact_file_name", false),
            JsonUtil.text(value, "artifact_platform", false),
            JsonUtil.text(value, "artifact_arch", false),
            JsonUtil.text(value, "authz_protocol", false),
            JsonUtil.boolValue(value, "host_integrity_required", false),
            JsonUtil.longValue(value, "size", 0),
            JsonUtil.boolValue(value, "rollback_allowed", false),
            maintenanceFromJson(value.get("maintenance")));
    }

    private static SwmModels.UpdateEvent eventFromJson(JsonNode value, SseEvent event) {
        return new SwmModels.UpdateEvent(
            JsonUtil.text(value, "id", false).isBlank() ? event.id
                : JsonUtil.text(value, "id", false),
            JsonUtil.text(value, "event_type", false).isBlank()
                ? event.name : JsonUtil.text(value, "event_type", false),
            JsonUtil.text(value, "org_id", false),
            JsonUtil.text(value, "app_id", false),
            JsonUtil.text(value, "device_id", false),
            JsonUtil.text(value, "channel_code", false),
            JsonUtil.text(value, "platform", false),
            JsonUtil.text(value, "arch", false),
            JsonUtil.text(value, "release_id", false),
            JsonUtil.text(value, "published_at", false),
            JsonUtil.text(value, "reason", false),
            JsonUtil.text(value, "message", false),
            JsonUtil.text(value, "maintenance_start_at", false));
    }

    private static SwmModels.OperationGrant grantFromJson(JsonNode value, byte[] challenge) {
        var grant = new SwmModels.OperationGrant(
            JsonUtil.text(value, "schema"),
            JsonUtil.text(value, "app_id"),
            JsonUtil.text(value, "release_id"),
            JsonUtil.text(value, "device_id"),
            JsonUtil.text(value, "device_key_id"),
            JsonUtil.text(value, "key_thumbprint"),
            JsonUtil.text(value, "device_public_key"),
            JsonUtil.text(value, "authz_public_key"),
            JsonUtil.text(value, "authz_key_id"),
            JsonUtil.text(value, "authz_root_trust_key_id"),
            JsonUtil.text(value, "authz_root_trust_signature"),
            JsonUtil.text(value, "session", false),
            JsonUtil.text(value, "grant_id"),
            JsonUtil.text(value, "operation"),
            JsonUtil.text(value, "plan_sha256"),
            JsonUtil.intValue(value, "step_count", 0),
            JsonUtil.longValue(value, "total_bytes", 0),
            JsonUtil.longValue(value, "issued_at", 0),
            JsonUtil.longValue(value, "expires_at", 0),
            JsonUtil.text(value, "consumer_challenge"),
            JsonUtil.text(value, "integrity_manifest_sha256", false),
            JsonUtil.text(value, "host_exe_sha256", false),
            JsonUtil.text(value, "consumer_module"),
            JsonUtil.text(value, "consumer_module_sha256", false));
        validateGrant(grant);
        return grant;
    }

    private static SwmModels.OperationConsumptionReceipt receiptFromJson(JsonNode value) {
        var receipt = new SwmModels.OperationConsumptionReceipt(
            JsonUtil.text(value, "schema"),
            JsonUtil.text(value, "grant_id"),
            JsonUtil.text(value, "operation"),
            JsonUtil.text(value, "plan_sha256"),
            JsonUtil.intValue(value, "step_count", 0),
            JsonUtil.longValue(value, "total_bytes", 0),
            JsonUtil.text(value, "consumer_challenge"),
            JsonUtil.longValue(value, "consumed_at", 0),
            JsonUtil.longValue(value, "expires_at", 0),
            JsonUtil.text(value, "integrity_manifest_sha256", false),
            JsonUtil.text(value, "host_exe_sha256", false),
            JsonUtil.text(value, "consumer_module"),
            JsonUtil.text(value, "consumer_module_sha256", false));
        if (!"operation_consume_receipt_v2".equals(receipt.schema())
            || !validUuid(receipt.grantId()) || receipt.operation().isBlank()
            || receipt.planSha256().isBlank() || receipt.consumerChallenge().isBlank()
            || receipt.consumerModule().isBlank() || receipt.stepCount() <= 0
            || receipt.consumedAt() <= 0 || receipt.expiresAt() <= receipt.consumedAt()) {
            throw new SwmException.Protocol("operation consumption receipt is invalid");
        }
        return receipt;
    }

    private boolean validateOperationRequest(
        SwmModels.OperationAuthorizationRequest request) {
        if (request == null || request.operation() == null || request.operation().isBlank()
            || request.plan() == null || request.plan().length == 0
            || request.stepCount() < 1 || request.stepCount() > 100000
            || request.consumerModule() == null || request.consumerModule().isBlank()) {
            throw new SwmException.Validation("operation authorization request is invalid");
        }
        var host = request.hostExecutablePath() != null;
        var module = request.consumerModulePath() != null;
        if (host != module) {
            throw new SwmException.Validation(
                "hostExecutablePath and consumerModulePath must be provided together");
        }
        var hostBound = host || pipeline.hostIntegrityRequired();
        if (hostBound && !host) {
            throw new SwmException.Validation(
                "host-bound authorization requires hostExecutablePath and consumerModulePath");
        }
        return hostBound;
    }

    private static void validateGrant(SwmModels.OperationGrant grant) {
        if (grant == null || grant.schema() == null
            || !(grant.schema().equals("operation_grant_v3_host")
                || grant.schema().equals("operation_grant_v3_unbound"))
            || !validUuid(grant.grantId()) || grant.operation() == null
            || grant.operation().isBlank() || grant.planSha256() == null
            || grant.consumerModule() == null || grant.consumerChallenge() == null
            || grant.stepCount() <= 0 || grant.issuedAt() <= 0
            || grant.expiresAt() <= grant.issuedAt()) {
            throw new SwmException.Validation("operation grant is incomplete or invalid");
        }
    }

    private void verifyArtifactManifest(SwmModels.UpdateInfo update) {
        if (!update.updateAvailable() || update.openInBrowser()
            || update.deliveryMethod().equalsIgnoreCase("external_link")) {
            return;
        }
        if (update.releaseId().isBlank() || update.version().isBlank()
            || update.downloadUrl().isBlank() || update.artifactFileName().isBlank()
            || update.manifestKeyId().isBlank() || update.manifestPublicKey().isBlank()
            || update.rootTrustKeyId().isBlank() || update.rootTrustSignature().isBlank()
            || update.signature().isBlank() || update.checksumSha256().length() != 64
            || update.size() <= 0) {
            throw new SwmException.Integrity(0, "artifact_manifest_incomplete",
                "signed artifact manifest is incomplete", "");
        }
        if (!update.rootTrustKeyId().equals(options().rootTrustKeyId())) {
            throw new SwmException.Integrity(0, "artifact_root_trust_mismatch",
                "artifact root trust key does not match", "");
        }
        var rootCanonical = "root_trust_manifest_v1\napp_id:" + options().appId()
            + "\nsigner_key_id:" + options().rootTrustKeyId()
            + "\nkey_id:" + update.manifestKeyId()
            + "\npublic_key:" + update.manifestPublicKey();
        if (!CryptoUtil.verifyEd25519(options().rootTrustPublicKey(),
            rootCanonical.getBytes(StandardCharsets.UTF_8), update.rootTrustSignature())) {
            throw new SwmException.Integrity(0, "artifact_root_trust_invalid",
                "artifact root trust signature is invalid", "");
        }
        var canonical = "artifact_manifest_v1\nrelease_id:" + update.releaseId()
            + "\nrelease_version:" + update.version()
            + "\nversion_code:" + (update.versionCode() == null ? "" : update.versionCode())
            + "\nplatform:" + update.artifactPlatform().toLowerCase(Locale.ROOT)
            + "\narch:" + update.artifactArch().toLowerCase(Locale.ROOT)
            + "\nsize:" + update.size()
            + "\nsha256:" + update.checksumSha256().toLowerCase(Locale.ROOT)
            + "\nkey_id:" + update.manifestKeyId();
        if (!CryptoUtil.verifyEd25519(update.manifestPublicKey(),
            canonical.getBytes(StandardCharsets.UTF_8), update.signature())) {
            throw new SwmException.Integrity(0, "artifact_manifest_signature_invalid",
                "artifact manifest signature is invalid", "");
        }
    }

    private void verifyDownload(SwmModels.UpdateInfo update, Path path) {
        try {
            var actual = CryptoUtil.sha256Hex(Files.readAllBytes(path));
            if (!actual.equalsIgnoreCase(update.checksumSha256())) {
                throw new SwmException.Integrity(0, "artifact_checksum_mismatch",
                    "downloaded artifact SHA-256 does not match", "");
            }
            verifyArtifactManifest(update);
        } catch (IOException exception) {
            throw new SwmException.Network("cannot hash downloaded artifact", exception);
        }
    }

    private boolean validDownloadUrl(String value) {
        try {
            var uri = URI.create(value);
            var base = options.baseUri();
            return uri.getScheme() != null && uri.getHost() != null
                && uri.getScheme().equalsIgnoreCase(base.getScheme())
                && uri.getHost().equalsIgnoreCase(base.getHost())
                && uri.getPort() == base.getPort()
                && uri.getPath().matches("/api/client/artifacts/[^/]+/download");
        } catch (RuntimeException exception) {
            return false;
        }
    }

    private static String resolveRedirect(String current, String location) {
        var base = URI.create(current);
        if (location.startsWith("//")) {
            return base.getScheme() + ":" + location;
        }
        return base.resolve(location).toString();
    }

    private static long parseTotal(String contentRange) {
        try {
            return Long.parseLong(contentRange.substring(contentRange.indexOf('/') + 1));
        } catch (RuntimeException exception) {
            throw new SwmException.Protocol("invalid Content-Range");
        }
    }

    private static String firstHeader(Map<String, List<String>> headers, String name) {
        for (var entry : headers.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(name) && !entry.getValue().isEmpty()) {
                return entry.getValue().get(0);
            }
        }
        return null;
    }

    private static String urlEncode(String value) {
        return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static long backoff(SwmModels.UpdateStreamOptions options, int attempt) {
        var base = Math.min(options.reconnectMaxBackoff().toMillis(),
            options.reconnectBackoff().toMillis() * (1L << Math.min(attempt, 4)));
        if (options.jitter()) {
            base += ThreadLocalRandom.current().nextLong(Math.max(1, base / 2));
        }
        return base;
    }

    private static void putIfPresent(ObjectNode node, String name, String value) {
        if (value != null && !value.isBlank()) {
            node.put(name, value);
        }
    }

    private static boolean validUuid(String value) {
        try {
            return value != null && UUID.fromString(value).toString().equalsIgnoreCase(value);
        } catch (RuntimeException exception) {
            return false;
        }
    }

    private static void validateOptions(SwmClientOptions options) {
        if (options.appId() == null || options.releaseId() == null
            || !options.appId().matches("[0-9a-fA-F-]{36}")
            || !options.releaseId().matches("[0-9a-fA-F-]{36}")) {
            throw new SwmException.Configuration("appId and releaseId must be UUID values");
        }
        try {
            if (CryptoUtil.decodeKeyMaterial(options.rootTrustPublicKey()).length != 32) {
                throw new SwmException.Configuration("rootTrustPublicKey must contain 32 bytes");
            }
        } catch (SwmException exception) {
            throw new SwmException.Configuration("rootTrustPublicKey is invalid");
        }
        options.baseUri();
        options.webBaseUri();
    }

    private SwmClientOptions options() {
        return options;
    }

    private static final class SseEvent {
        String name = "";
        String id = "";
        StringBuilder data = new StringBuilder();
    }
}
