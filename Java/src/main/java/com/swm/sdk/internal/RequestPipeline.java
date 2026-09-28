package com.swm.sdk.internal;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.swm.sdk.HttpTransport;
import com.swm.sdk.SwmClientOptions;
import com.swm.sdk.SwmException;
import com.swm.sdk.SwmModels;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;

public final class RequestPipeline implements AutoCloseable {
    public enum Operation {
        TIME, KEY_MANIFEST, UPDATE_CHECK, HEARTBEAT, EVENT, FEEDBACK, ENROLLMENT,
        ROTATE, AUTHORIZE, CONSUME, DOWNLOAD, UPDATE_STREAM, FIRMWARE, DEBUG
    }

    public record Request(
        String method,
        String path,
        Operation operation,
        byte[] body,
        boolean encryptBody,
        boolean requireSession,
        boolean requireTrustedTime,
        boolean requireOnlineKey,
        String contentType,
        String query,
        String dpopResource
    ) {}

    public record Response(int statusCode, byte[] body, String requestNonce,
                           Map<String, List<String>> headers) {}

    private record Policy(Duration timeout, int retries, Duration backoff,
                          Duration maxBackoff, Duration deadline) {}

    private record OnlineKey(String keyId, String publicKey, long issuedAt, long refreshAfter) {}

    private final SwmClientOptions options;
    private final StateStore store;
    private final HttpTransport transport;
    private final TrustedClock clock = new TrustedClock();
    private final ReentrantLock refreshLock = new ReentrantLock();
    private final Object stateLock = new Object();
    private DeviceIdentity identity;
    private SwmModels.HardwareEvidence hardware;
    private OnlineKey currentKey;
    private final Deque<OnlineKey> previousKeys = new ArrayDeque<>();
    private String session;
    private long sessionExpiresAt;
    private boolean hostIntegrityRequired;

    public RequestPipeline(SwmClientOptions options, HttpTransport transport) {
        this.options = options;
        this.transport = transport == null
            ? new JdkHttpTransport(Duration.ofSeconds(10)) : transport;
        this.store = new StateStore(options.appId(), options.storageDirectory());
        var hostIntegrityOptions = options.hostIntegrity();
        var host = new HostIntegrity(options, store);
        this.hostIntegrityRequired = host.readCachedPolicy();
    }

    public String deviceId() {
        return options.deviceId() == null || options.deviceId().isBlank()
            ? identity().deviceId() : options.deviceId();
    }

    public String installId() { return identity().installId(); }
    public String deviceKeyId() { return identity().keyId(); }
    public String session() { return session; }
    public TrustedClock clock() { return clock; }
    public boolean hostIntegrityRequired() { return hostIntegrityRequired; }
    public SwmModels.HardwareEvidence hardware() {
        synchronized (stateLock) {
            if (hardware == null) {
                hardware = HardwareEvidence.collect(options.appId());
            }
            return hardware;
        }
    }

    public ObjectNode createDeviceAuth(String challenge) {
        var value = hardware();
        var result = JsonUtil.object();
        result.put("install_id", identity().installId());
        result.put("key_id", identity().keyId());
        result.put("key_thumbprint", identity().keyThumbprint());
        result.put("public_key_sec1", identity().publicKeySec1());
        result.put("credential_version", "device_credential_v2");
        var evidence = result.putObject("hardware_evidence");
        evidence.put("version", value.version());
        evidence.put("component_mask", value.componentMask());
        evidence.put("aggregate_hash", value.aggregateHash());
        if (challenge != null && !challenge.isBlank()) {
            result.put("challenge", challenge);
        }
        return result;
    }

    public void refreshOnlineKeys(boolean force) {
        if (!force && hasFreshKey()) {
            return;
        }
        refreshLock.lock();
        try {
            if (!force && hasFreshKey()) {
                return;
            }
            try {
                if (!clock.initialized()) {
                    refreshTrustedTime();
                }
                refreshOnlineKeysCore();
            } catch (SwmException exception) {
                if (!canUseCurrentKeyAfterFailure() || (exception.kind() != SwmException.Kind.NETWORK
                    && exception.kind() != SwmException.Kind.TIMEOUT
                    && exception.statusCode() < 500)) {
                    throw exception;
                }
            }
        } finally {
            refreshLock.unlock();
        }
    }

    public Response send(Request request) {
        if (request.requireTrustedTime() && !clock.initialized()) {
            refreshTrustedTime();
        }
        if (request.requireOnlineKey()) {
            refreshOnlineKeys(false);
        }
        if (request.requireSession()) {
            ensureSession();
        }
        var policy = policy(request.operation());
        var started = TrustedClock.tickMs();
        SwmException lastError = null;
        for (int attempt = 0; attempt <= policy.retries(); attempt++) {
            if (deadlineExceeded(policy, started)) {
                break;
            }
            try {
                var response = sendAttempt(request);
                if (isTransient(response.statusCode()) && attempt < policy.retries()) {
                    sleep(policy.backoff());
                    continue;
                }
                return response;
            } catch (SwmException exception) {
                if (exception.kind() != SwmException.Kind.NETWORK
                    && exception.kind() != SwmException.Kind.TIMEOUT) {
                    throw exception;
                }
                lastError = exception;
                if (attempt < policy.retries()) {
                    sleep(policy.backoff());
                }
            }
        }
        if (lastError != null) {
            throw lastError;
        }
        throw new SwmException.Timeout("request deadline exceeded");
    }

    public JsonNode sendAndVerify(Request request) {
        return verifyAuthz(send(request));
    }

    public Response sendWeb(String method, String path, byte[] body, Operation operation,
                            boolean includeDpop, JsonNode debugCredentials,
                            String watchToken, String requestId) {
        if (!clock.initialized()) {
            refreshTrustedTime();
        }
        var uri = absoluteWeb(path);
        var sessionValue = includeDpop || debugCredentials != null ? ensureSession() : "";
        var headers = new java.util.LinkedHashMap<String, List<String>>();
        add(headers, "Accept", "application/json");
        if (body != null && body.length > 0) {
            add(headers, "Content-Type", "application/json; charset=utf-8");
        }
        if (includeDpop) {
            add(headers, "X-SWM-Session", sessionValue);
            add(headers, "X-SWM-DPoP", createDpop(method, uri.toString(), sessionValue,
                body == null ? new byte[0] : body));
        }
        if (debugCredentials != null) {
            var timestamp = Long.toString(clock.nowUnixSeconds());
            var nonce = CryptoUtil.hex(CryptoUtil.randomBytes(16));
            var clientId = JsonUtil.text(debugCredentials, "client_id");
            var secret = JsonUtil.text(debugCredentials, "client_secret");
            var canonical = method + "\n" + path + "\n\n"
                + CryptoUtil.sha256Hex(body == null ? new byte[0] : body) + "\n"
                + timestamp + "\n" + nonce + "\n" + clientId;
            add(headers, "X-Client-ID", clientId);
            add(headers, "X-Timestamp", timestamp);
            add(headers, "X-Nonce", nonce);
            add(headers, "X-Signature-Version", "1");
            add(headers, "X-Signature", CryptoUtil.hex(CryptoUtil.hmacSha256(
                secret.getBytes(StandardCharsets.UTF_8), canonical.getBytes(StandardCharsets.UTF_8))));
        }
        if (watchToken != null && !watchToken.isBlank()) {
            add(headers, "X-Debug-Watch-Token", watchToken);
        }
        if (requestId != null && !requestId.isBlank()) {
            add(headers, "X-Debug-Request-Id", requestId);
        }
        var response = transport.send(new HttpTransport.Request(method, uri, headers,
            body == null ? new byte[0] : body, policy(operation).timeout()),
            policy(operation).timeout());
        return new Response(response.statusCode(), response.body(), randomUuid(), response.headers());
    }

    public HttpTransport.StreamResponse openUpdateStream(String url, String[] nonce) {
        if (!clock.initialized()) {
            refreshTrustedTime();
        }
        var sessionValue = ensureSession();
        nonce[0] = randomUuid();
        var headers = new java.util.LinkedHashMap<String, List<String>>();
        add(headers, "Accept", "text/event-stream");
        add(headers, "X-App-Id", options.appId());
        add(headers, "X-Timestamp", Long.toString(clock.nowUnixSeconds()));
        add(headers, "X-Nonce", nonce[0]);
        add(headers, "X-Authz-Capability", "v3");
        add(headers, "X-Client-Release-Id", options.releaseId());
        add(headers, "X-Client-Version", options.version());
        add(headers, "X-Client-Version-Code",
            options.versionCode() == null ? "" : options.versionCode().toString());
        add(headers, "X-SWM-Session", sessionValue);
        add(headers, "X-SWM-DPoP", createDpop("GET", url, sessionValue, new byte[0]));
        return transport.stream(new HttpTransport.Request("GET", URI.create(url), headers,
            new byte[0], policy(Operation.UPDATE_STREAM).timeout()),
            policy(Operation.UPDATE_STREAM).timeout());
    }

    public HttpTransport.StreamResponse openWebStream(
        String path,
        String requestId,
        JsonNode debugCredentials,
        String watchToken,
        String[] nonce
    ) {
        if (!clock.initialized()) {
            refreshTrustedTime();
        }
        var uri = absoluteWeb(path);
        var sessionValue = ensureSession();
        nonce[0] = CryptoUtil.hex(CryptoUtil.randomBytes(16));
        var timestamp = Long.toString(clock.nowUnixSeconds());
        var clientId = JsonUtil.text(debugCredentials, "client_id");
        var secret = JsonUtil.text(debugCredentials, "client_secret");
        var canonical = "GET\n" + path + "\n\n" + CryptoUtil.sha256Hex(new byte[0])
            + "\n" + timestamp + "\n" + nonce[0] + "\n" + clientId;
        var headers = new java.util.LinkedHashMap<String, List<String>>();
        add(headers, "Accept", "text/event-stream");
        add(headers, "X-Client-ID", clientId);
        add(headers, "X-Timestamp", timestamp);
        add(headers, "X-Nonce", nonce[0]);
        add(headers, "X-Signature-Version", "1");
        add(headers, "X-Signature", CryptoUtil.hex(CryptoUtil.hmacSha256(
            secret.getBytes(StandardCharsets.UTF_8), canonical.getBytes(StandardCharsets.UTF_8))));
        add(headers, "X-SWM-Session", sessionValue);
        add(headers, "X-SWM-DPoP", createDpop("GET", uri.toString(), sessionValue, new byte[0]));
        add(headers, "X-Debug-Watch-Token", watchToken);
        add(headers, "X-Debug-Request-Id", requestId);
        return transport.stream(new HttpTransport.Request("GET", uri, headers,
            new byte[0], policy(Operation.DEBUG).timeout()), policy(Operation.DEBUG).timeout());
    }

    public HttpTransport.StreamResponse openDownloadStream(String url, long rangeStart,
                                                            boolean authenticated) {
        var headers = new java.util.LinkedHashMap<String, List<String>>();
        if (rangeStart > 0) {
            add(headers, "Range", "bytes=" + rangeStart + "-");
        }
        if (authenticated) {
            if (!clock.initialized()) {
                refreshTrustedTime();
            }
            var sessionValue = ensureSession();
            add(headers, "X-SWM-Session", sessionValue);
            add(headers, "X-SWM-DPoP", createDpop("GET", url, sessionValue, new byte[0]));
        }
        return transport.stream(new HttpTransport.Request("GET", URI.create(url), headers,
            new byte[0], policy(Operation.DOWNLOAD).timeout()),
            policy(Operation.DOWNLOAD).timeout());
    }

    public boolean offlineLocked() {
        var value = store.readProtected("offline.bin");
        if (value.isEmpty()) {
            return true;
        }
        var lines = new String(value.get(), StandardCharsets.UTF_8).split("\n", -1);
        if (lines.length < 4 || !"SwmSdkOfflineBudgetV1".equals(lines[0])
            || !identity().installId().equals(lines[1])
            || !identity().keyThumbprint().equals(lines[2])) {
            return true;
        }
        try {
            var last = Long.parseLong(lines[3]);
            var now = clock.nowUnixMs();
            return now <= 0 || now < last || now - last > 24L * 60 * 60 * 1000;
        } catch (NumberFormatException exception) {
            return true;
        }
    }

    public void noteVerifiedInteraction() {
        var now = clock.nowUnixMs();
        if (now <= 0) {
            return;
        }
        var text = "SwmSdkOfflineBudgetV1\n" + identity().installId() + "\n"
            + identity().keyThumbprint() + "\n" + now + "\n";
        store.writeProtected("offline.bin", text.getBytes(StandardCharsets.UTF_8));
    }

    public void setHostIntegrityRequired(boolean value) {
        hostIntegrityRequired = value;
        new HostIntegrity(options, store).storePolicy(value);
    }

    public JsonNode verifyAuthz(Response response) {
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throwIfError(response);
        }
        var rawData = JsonUtil.rawMember(response.body(), "data");
        var carrier = JsonUtil.parse(response.body(), "Authz v3 carrier");
        var authz = carrier.get("authz");
        if (rawData == null || authz == null || !authz.isObject()) {
            throw new SwmException.Protocol("Authz v3 carrier is incomplete");
        }
        var version = JsonUtil.text(authz, "version");
        var decision = JsonUtil.text(authz, "decision");
        var release = JsonUtil.text(authz, "release_id");
        var device = JsonUtil.text(authz, "device_id");
        var nonce = JsonUtil.text(authz, "nonce");
        var dataHash = JsonUtil.text(authz, "data_sha256");
        var keyId = JsonUtil.text(authz, "key_id");
        var reason = JsonUtil.text(authz, "reason", false);
        var sessionValue = JsonUtil.text(authz, "session", false);
        var signature = JsonUtil.text(authz, "signature");
        var issuedAt = JsonUtil.longValue(authz, "issued_at", 0);
        var expiresAt = JsonUtil.longValue(authz, "expires_at", 0);
        var now = clock.nowUnixSeconds();
        if (!"authz_v3".equals(version) || !"allow".equals(decision)
            || !options.releaseId().equals(release) || !deviceId().equals(device)
            || !response.requestNonce().equals(nonce) || issuedAt <= 0
            || expiresAt <= issuedAt || expiresAt - issuedAt > 900
            || issuedAt > now + 120 || expiresAt < now - 120) {
            throw new SwmException.Session(403, "authz_invalid",
                "Authz v3 response identity or lifetime is invalid");
        }
        if (!dataHash.equalsIgnoreCase(CryptoUtil.sha256Hex(rawData))) {
            throw new SwmException.Integrity(403, "authz_data_mismatch",
                "Authz v3 response data hash is invalid", "");
        }
        var key = findKey(keyId);
        if (key == null) {
            throw new SwmException.Session(403, "authz_invalid",
                "Authz v3 response key is unknown");
        }
        var canonical = "authz_v3\napp_id:" + options.appId() + "\nrelease_id:" + release
            + "\ndevice_id:" + device + "\nnonce:" + nonce + "\ndecision:" + decision
            + "\nreason:" + reason + "\ndata_sha256:" + dataHash + "\nsession:" + sessionValue
            + "\nissued_at:" + issuedAt + "\nexpires_at:" + expiresAt + "\nkey_id:" + keyId;
        if (!CryptoUtil.verifyEd25519(key.publicKey(),
            canonical.getBytes(StandardCharsets.UTF_8), signature)) {
            throw new SwmException.Integrity(403, "authz_signature_invalid",
                "Authz v3 response signature is invalid", "");
        }
        if (!sessionValue.isBlank()) {
            session = sessionValue;
            sessionExpiresAt = expiresAt;
        }
        noteVerifiedInteraction();
        return carrier.get("data");
    }

    public void throwIfError(Response response) {
        if (response.statusCode() >= 200 && response.statusCode() < 300) {
            return;
        }
        var body = new String(response.body(), StandardCharsets.UTF_8);
        String code = "";
        String message = body;
        try {
            var root = JsonUtil.parse(response.body(), "service error");
            var error = root.get("error");
            if (error != null && error.isObject()) {
                code = JsonUtil.text(error, "code", false);
                message = JsonUtil.text(error, "message", false);
            } else if (error != null && error.isTextual()) {
                message = error.asText();
                code = message;
            } else {
                code = JsonUtil.text(root, "code", false);
                message = JsonUtil.text(root, "message", false);
            }
        } catch (RuntimeException ignored) {
            // Preserve raw response text.
        }
        if ("device_blocked".equals(code)) {
            throw new SwmException(SwmException.Kind.DEVICE_BLOCKED,
                response.statusCode(), code, message, body);
        }
        if ("client_version_unsupported".equals(code)) {
            throw new SwmException(SwmException.Kind.UNSUPPORTED_VERSION,
                response.statusCode(), code, message, body);
        }
        if ("update_region_blocked".equals(code)) {
            throw new SwmException(SwmException.Kind.UPDATE_REGION_BLOCKED,
                response.statusCode(), code, message, body);
        }
        if ("feedback_disabled".equals(code)) {
            throw new SwmException(SwmException.Kind.FEEDBACK_DISABLED,
                response.statusCode(), code, message, body);
        }
        if (code.startsWith("release_integrity_")) {
            throw new SwmException.Integrity(response.statusCode(), code, message, body);
        }
        if (code.startsWith("operation_auth_") || code.startsWith("operation_grant_")) {
            throw new SwmException.OperationAuthorization(response.statusCode(), code, message);
        }
        if (response.statusCode() == 401) {
            throw new SwmException.Session(response.statusCode(), code, message);
        }
        if (response.statusCode() == 403) {
            throw new SwmException(SwmException.Kind.UNAUTHORIZED,
                response.statusCode(), code, message, body);
        }
        if (response.statusCode() == 429) {
            throw new SwmException(SwmException.Kind.RATE_LIMIT,
                response.statusCode(), code, message, body);
        }
        throw new SwmException(response.statusCode() >= 500 ? SwmException.Kind.API
            : SwmException.Kind.VALIDATION, response.statusCode(), code, message, body);
    }

    public SwmModels.DeviceKeyRotationResult rotateDeviceKey() {
        if (!clock.initialized()) {
            refreshTrustedTime();
        }
        refreshOnlineKeys(false);
        ensureSession();
        var pending = DeviceIdentity.createPending(options.appId(), store);
        boolean committed = false;
        try {
            String challenge = "";
            String proofDigest = "";
            for (int attempt = 0; attempt < 2; attempt++) {
                var payload = JsonUtil.object();
                payload.set("new_device_auth", createDeviceAuth(challenge, pending));
                if (!challenge.isBlank()) {
                    var digest = CryptoUtil.unhex(proofDigest);
                    if (digest.length != 32) {
                        throw new SwmException.Protocol("device rotation challenge is invalid");
                    }
                    payload.put("new_key_proof", CryptoUtil.base64Url(pending.signSha256(digest)));
                }
                var response = send(request("POST", "/api/client/device-key/rotate",
                    Operation.ROTATE, JsonUtil.bytes(payload), true, true,
                    true, true, "application/json; charset=utf-8", "", ""));
                if (response.statusCode() == 428 && attempt == 0) {
                    var body = JsonUtil.parse(response.body(), "device key rotation challenge");
                    challenge = JsonUtil.text(body, "challenge");
                    proofDigest = JsonUtil.text(body, "proof_digest");
                    continue;
                }
                throwIfError(response);
                var result = JsonUtil.parse(response.body(), "device key rotation response");
                if (!JsonUtil.boolValue(result, "rotated", false)
                    || !pending.installId().equals(JsonUtil.text(result, "install_id", false))
                    || !pending.keyId().equals(JsonUtil.text(result, "key_id", false))) {
                    throw new SwmException.Protocol("device key rotation response is invalid");
                }
                pending.commitPending();
                synchronized (stateLock) {
                    identity().close();
                    identity = pending;
                }
                committed = true;
                session = null;
                sessionExpiresAt = 0;
                return new SwmModels.DeviceKeyRotationResult(
                    JsonUtil.text(result, "registration_id", false), pending.installId(),
                    pending.keyId(), deviceId());
            }
            throw new SwmException.Protocol("device key rotation challenge retry was exhausted");
        } catch (RuntimeException exception) {
            if (!committed) {
                pending.deletePending();
            }
            throw exception;
        }
    }

    private ObjectNode createDeviceAuth(String challenge, DeviceIdentity pending) {
        var value = hardware();
        var result = JsonUtil.object();
        result.put("install_id", pending.installId());
        result.put("key_id", pending.keyId());
        result.put("key_thumbprint", pending.keyThumbprint());
        result.put("public_key_sec1", pending.publicKeySec1());
        result.put("credential_version", "device_credential_v2");
        var evidence = result.putObject("hardware_evidence");
        evidence.put("version", value.version());
        evidence.put("component_mask", value.componentMask());
        evidence.put("aggregate_hash", value.aggregateHash());
        if (challenge != null && !challenge.isBlank()) {
            result.put("challenge", challenge);
        }
        return result;
    }

    private Response sendAttempt(Request request) {
        var timestamp = request.requireTrustedTime()
            ? Long.toString(clock.nowUnixSeconds())
            : Long.toString(System.currentTimeMillis() / 1000);
        var nonce = randomUuid();
        var uri = absolute(request.path(), request.query());
        var headers = new java.util.LinkedHashMap<String, List<String>>();
        add(headers, "X-App-Id", options.appId());
        add(headers, "X-Timestamp", timestamp);
        add(headers, "X-Nonce", nonce);
        add(headers, "X-Authz-Capability", "v3");
        add(headers, "X-Client-Release-Id", options.releaseId());
        add(headers, "X-Client-Version", options.version());
        add(headers, "X-Client-Version-Code",
            options.versionCode() == null ? "" : options.versionCode().toString());
        var body = request.body() == null ? new byte[0] : request.body();
        if (request.requireOnlineKey()) {
            var key = currentKey();
            var sessionBinding = request.requireSession() ? ensureSession() : "";
            add(headers, "X-SWM-DPoP", createDpop(request.method(),
                request.dpopResource() == null ? uri.toString() : request.dpopResource(),
                sessionBinding, body));
            if (request.requireSession()) {
                add(headers, "X-SWM-Session", sessionBinding);
            }
            if (request.encryptBody()) {
                body = CryptoUtil.encryptRequestBody(request.method(), request.path(),
                    canonicalQuery(request.query()), Long.parseLong(timestamp), nonce,
                    options.appId(), options.releaseId(), options.version(),
                    options.versionCode() == null ? "" : options.versionCode().toString(),
                    key.keyId(), key.publicKey(), body);
                add(headers, "X-SWM-Body-Enc", "x25519-aes-gcm-v1");
                add(headers, "X-SWM-Online-Key-Id", key.keyId());
            }
        }
        if (request.contentType() != null && !request.contentType().isBlank()) {
            add(headers, "Content-Type", request.contentType());
        }
        var response = transport.send(new HttpTransport.Request(request.method(), uri, headers,
            body, policy(request.operation()).timeout()), policy(request.operation()).timeout());
        return new Response(response.statusCode(), response.body(), nonce, response.headers());
    }

    private void refreshTrustedTime() {
        var started = TrustedClock.tickMs();
        var response = send(new Request("GET", "/api/client/time", Operation.TIME,
            new byte[0], false, false, false, false, "", "", ""));
        var received = TrustedClock.tickMs();
        throwIfError(response);
        var body = JsonUtil.parse(response.body(), "signed server time");
        var version = JsonUtil.text(body, "manifest_version");
        var appId = JsonUtil.text(body, "app_id");
        var releaseId = JsonUtil.text(body, "release_id");
        var nonce = JsonUtil.text(body, "nonce");
        var rootKey = JsonUtil.text(body, "root_trust_key_id");
        var signature = JsonUtil.text(body, "signature");
        var serverTime = JsonUtil.longValue(body, "server_time_ms", 0);
        var expiresAt = JsonUtil.longValue(body, "expires_at_ms", 0);
        if (!"server_time_v1".equals(version) || !options.appId().equals(appId)
            || !options.releaseId().equals(releaseId) || !response.requestNonce().equals(nonce)
            || !options.rootTrustKeyId().equals(rootKey) || serverTime <= 0
            || expiresAt <= serverTime || expiresAt - serverTime > 60000) {
            throw new SwmException.Clock("signed server time identity is invalid");
        }
        var canonical = "server_time_v1\napp_id:" + appId + "\nrelease_id:" + releaseId
            + "\nnonce:" + nonce + "\nserver_time_ms:" + serverTime
            + "\nexpires_at_ms:" + expiresAt + "\nroot_trust_key_id:" + rootKey;
        if (!CryptoUtil.verifyEd25519(options.rootTrustPublicKey(),
            canonical.getBytes(StandardCharsets.UTF_8), signature)) {
            throw new SwmException.Clock("signed server time signature is invalid");
        }
        clock.setAuthoritativeTime(serverTime, started, received);
        noteVerifiedInteraction();
    }

    private void refreshOnlineKeysCore() {
        var response = send(new Request("GET", "/api/client/key-manifest", Operation.KEY_MANIFEST,
            new byte[0], false, false, true, false, "", "", ""));
        throwIfError(response);
        var manifest = JsonUtil.parse(response.body(), "online key manifest");
        var version = JsonUtil.text(manifest, "manifest_version");
        var purpose = JsonUtil.text(manifest, "purpose");
        var appId = JsonUtil.text(manifest, "app_id");
        var releaseId = JsonUtil.text(manifest, "release_id");
        var keyId = JsonUtil.text(manifest, "key_id");
        var publicKey = JsonUtil.text(manifest, "public_key");
        var rootId = JsonUtil.text(manifest, "root_trust_key_id");
        var signature = JsonUtil.text(manifest, "root_trust_signature");
        var issuedAt = JsonUtil.longValue(manifest, "issued_at", 0);
        var refreshAfter = JsonUtil.longValue(manifest, "refresh_after", 0);
        var now = clock.nowUnixSeconds();
        if (!"online_key_manifest_v1".equals(version) || !"online_body".equals(purpose)
            || !options.appId().equals(appId) || !options.releaseId().equals(releaseId)
            || !options.rootTrustKeyId().equals(rootId) || keyId.isBlank() || publicKey.isBlank()
            || issuedAt <= 0 || refreshAfter <= issuedAt
            || refreshAfter - issuedAt > 30L * 24 * 60 * 60
            || issuedAt > now + 120 || refreshAfter < now - 120) {
            throw new SwmException.Integrity(0, "online_key_manifest_invalid",
                "online key manifest identity or lifetime is invalid", "");
        }
        var canonical = "online_key_manifest_v1\npurpose:" + purpose + "\napp_id:" + appId
            + "\nrelease_id:" + releaseId + "\nkey_id:" + keyId + "\npublic_key:" + publicKey
            + "\nroot_trust_key_id:" + rootId + "\nissued_at:" + issuedAt
            + "\nrefresh_after:" + refreshAfter;
        if (!CryptoUtil.verifyEd25519(options.rootTrustPublicKey(),
            canonical.getBytes(StandardCharsets.UTF_8), signature)) {
            throw new SwmException.Integrity(0, "online_key_manifest_invalid",
                "online key manifest root signature is invalid", "");
        }
        installKey(new OnlineKey(keyId, publicKey, issuedAt, refreshAfter));
    }

    private void installKey(OnlineKey key) {
        synchronized (stateLock) {
            if (currentKey != null && currentKey.keyId().equals(key.keyId())) {
                if (!currentKey.publicKey().equals(key.publicKey())) {
                    throw new SwmException.Integrity(0, "online_key_manifest_invalid",
                        "online key id was rebound", "");
                }
                currentKey = key;
                return;
            }
            if (currentKey != null) {
                previousKeys.removeIf(value -> value.keyId().equals(key.keyId()));
                previousKeys.addFirst(currentKey);
                while (previousKeys.size() > 4) {
                    previousKeys.removeLast();
                }
            }
            currentKey = key;
        }
    }

    private OnlineKey currentKey() {
        synchronized (stateLock) {
            if (currentKey == null) {
                throw new SwmException.Session(401, "authz_key_required",
                    "online authorization key is unavailable");
            }
            if (clock.initialized() && clock.nowUnixSeconds() >= currentKey.refreshAfter()) {
                throw new SwmException.Session(401, "authz_key_expired",
                    "online authorization key has expired");
            }
            return currentKey;
        }
    }

    private OnlineKey findKey(String keyId) {
        synchronized (stateLock) {
            if (currentKey != null && currentKey.keyId().equals(keyId)) {
                return currentKey;
            }
            return previousKeys.stream().filter(value -> value.keyId().equals(keyId))
                .findFirst().orElse(null);
        }
    }

    private boolean hasFreshKey() {
        synchronized (stateLock) {
            return currentKey != null && clock.initialized()
                && clock.nowUnixSeconds() < currentKey.refreshAfter() - 300;
        }
    }

    private boolean canUseCurrentKeyAfterFailure() {
        synchronized (stateLock) {
            return currentKey != null && clock.initialized()
                && clock.nowUnixSeconds() < currentKey.refreshAfter();
        }
    }

    private String ensureSession() {
        if (!clock.initialized()) {
            throw new SwmException.Clock("trusted server time is unavailable");
        }
        if (session == null || sessionExpiresAt <= clock.nowUnixSeconds()) {
            throw new SwmException.Session(401, "authz_session_invalid",
                "authorization session is missing or expired");
        }
        return session;
    }

    private DeviceIdentity identity() {
        synchronized (stateLock) {
            if (identity == null) {
                identity = DeviceIdentity.loadOrCreate(options.appId(), store);
            }
            return identity;
        }
    }

    private URI absolute(String path, String query) {
        var base = options.baseUri().toString();
        if (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        return URI.create(base + path + (query == null || query.isBlank() ? "" : "?" + query));
    }

    private URI absoluteWeb(String path) {
        var base = options.webBaseUri().toString();
        if (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        return URI.create(base + path);
    }

    private String createDpop(String method, String url, String sessionBinding, byte[] body) {
        var now = clock.nowUnixSeconds();
        if (now <= 0) {
            throw new SwmException.Clock("trusted server time is unavailable");
        }
        var header = JsonUtil.object();
        header.put("alg", "ES256");
        header.put("kid", deviceKeyId());
        header.put("typ", "swm-dpop+jwt");
        var payload = JsonUtil.object();
        payload.put("app_id", options.appId());
        payload.put("ath", CryptoUtil.base64Url(CryptoUtil.sha256(
            sessionBinding.getBytes(StandardCharsets.UTF_8))));
        payload.put("body_sha256", CryptoUtil.sha256Hex(body));
        payload.put("channel", options.channel());
        payload.put("device_id", deviceId());
        payload.put("exp", now + 60);
        payload.put("htm", method);
        payload.put("htu", url);
        payload.put("iat", now);
        payload.put("install_id", installId());
        payload.put("jti", CryptoUtil.hex(CryptoUtil.randomBytes(16)));
        payload.put("pcid", deviceId());
        payload.put("release_id", options.releaseId());
        var encodedHeader = CryptoUtil.base64Url(JsonUtil.bytes(header));
        var encodedPayload = CryptoUtil.base64Url(JsonUtil.bytes(payload));
        var signingInput = encodedHeader + "." + encodedPayload;
        var signature = identity().signSha256(CryptoUtil.sha256(
            signingInput.getBytes(StandardCharsets.UTF_8)));
        return signingInput + "." + CryptoUtil.base64Url(signature);
    }

    private static Request request(String method, String path, Operation operation, byte[] body,
                                   boolean encrypt, boolean session, boolean trustTime,
                                   boolean onlineKey, String contentType, String query,
                                   String dpopResource) {
        return new Request(method, path, operation, body, encrypt, session, trustTime,
            onlineKey, contentType, query, dpopResource);
    }

    private static String canonicalQuery(String query) {
        if (query == null || query.isBlank()) {
            return "";
        }
        var value = query.startsWith("?") ? query.substring(1) : query;
        return Arrays.stream(value.split("&"))
            .filter(item -> !item.isBlank())
            .map(item -> item.split("=", 2))
            .map(parts -> new String[]{
                encode(parts[0]), parts.length > 1 ? encode(parts[1]) : ""})
            .sorted(Comparator.comparing(part -> part[0] + "=" + part[1]))
            .map(part -> part[0] + "=" + part[1])
            .collect(Collectors.joining("&"));
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static void add(Map<String, List<String>> headers, String name, String value) {
        headers.computeIfAbsent(name, ignored -> new ArrayList<>()).add(value);
    }

    private static boolean isTransient(int status) {
        return status == 408 || status == 429 || status == 500 || status == 502
            || status == 503 || status == 504;
    }

    private static String randomUuid() {
        var bytes = CryptoUtil.randomBytes(16);
        bytes[6] = (byte) ((bytes[6] & 0x0f) | 0x40);
        bytes[8] = (byte) ((bytes[8] & 0x3f) | 0x80);
        var hex = CryptoUtil.hex(bytes);
        return hex.substring(0, 8) + "-" + hex.substring(8, 12) + "-"
            + hex.substring(12, 16) + "-" + hex.substring(16, 20) + "-" + hex.substring(20);
    }

    private static Policy policy(Operation operation) {
        return switch (operation) {
            case TIME, KEY_MANIFEST -> new Policy(Duration.ofSeconds(10), 2,
                Duration.ofSeconds(1), Duration.ofSeconds(4), Duration.ofSeconds(40));
            case UPDATE_CHECK -> new Policy(Duration.ofSeconds(15), 2,
                Duration.ofMillis(1500), Duration.ofSeconds(6), Duration.ofSeconds(60));
            case HEARTBEAT, EVENT -> new Policy(Duration.ofSeconds(8), 2,
                Duration.ofSeconds(1), Duration.ofSeconds(4), Duration.ofSeconds(30));
            case DOWNLOAD, UPDATE_STREAM -> new Policy(Duration.ofSeconds(30), 0,
                Duration.ZERO, Duration.ZERO, Duration.ZERO);
            case FIRMWARE, DEBUG -> new Policy(Duration.ofSeconds(8), 1,
                Duration.ofMillis(500), Duration.ofSeconds(1), Duration.ofSeconds(20));
            default -> new Policy(Duration.ofSeconds(10), 1,
                Duration.ofSeconds(1), Duration.ofSeconds(2), Duration.ofSeconds(24));
        };
    }

    private static boolean deadlineExceeded(Policy policy, long started) {
        return policy.deadline().toMillis() > 0
            && TrustedClock.tickMs() - started + policy.timeout().toMillis()
                > policy.deadline().toMillis();
    }

    private static void sleep(Duration duration) {
        try {
            Thread.sleep(duration.toMillis());
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new SwmException.Timeout("request interrupted");
        }
    }

    @Override
    public void close() {
        synchronized (stateLock) {
            if (identity != null) {
                identity.close();
                identity = null;
            }
        }
    }

}
