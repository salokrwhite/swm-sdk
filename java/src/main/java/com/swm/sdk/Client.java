package com.swm.sdk;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

public class Client {
    public static final String CONTROL_EVENT_SHUTDOWN = "device_shutdown";
    public static final String CONTROL_EVENT_MAINTENANCE_SCHEDULED = "maintenance_scheduled";
    public static final String CONTROL_EVENT_MAINTENANCE_CANCELLED = "maintenance_cancelled";
    public static final String API_ERROR_CODE_DEVICE_BLOCKED = "device_blocked";
    public static final String API_ERROR_CODE_UPDATE_REGION_BLOCKED = "update_region_blocked";
    public static final String API_ERROR_CODE_FEEDBACK_DISABLED = "feedback_disabled";

    private static final String SIGN_HEADER_APP_ID = "X-App-Id";
    private static final String SIGN_HEADER_TIMESTAMP = "X-Timestamp";
    private static final String SIGN_HEADER_NONCE = "X-Nonce";
    private static final String SIGN_HEADER_SIGNATURE = "X-Signature";
    private static final String SIGN_HEADER_VERSION = "X-Sign-Version";
    private static final String SIGN_VERSION_V1 = "v1";
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .setSerializationInclusion(JsonInclude.Include.NON_NULL)
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    private final String baseUrl;
    private final String appId;
    private final String appSecret;
    private final HttpClient httpClient;

    private String authToken = "";
    private String channel = "";
    private String platform = "";
    private String arch = "";
    private String deviceId = "";
    private String userId = "";
    private Map<String, Object> attributes = new LinkedHashMap<>();
    private String publicKey = "";
    private boolean verifySignature;
    private int retries = 2;
    private Duration backoff = Duration.ofMillis(500);

    public Client(String baseUrl, String appId, String appSecret) {
        this(baseUrl, appId, appSecret, HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(30))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build());
    }

    public Client(String baseUrl, String appId, String appSecret, HttpClient httpClient) {
        this.baseUrl = trimTrailingSlash(baseUrl);
        this.appId = appId;
        this.appSecret = appSecret;
        this.httpClient = httpClient;
    }

    public String getBaseUrl() { return baseUrl; }
    public String getAppId() { return appId; }
    public String getAppSecret() { return appSecret; }
    public String getAuthToken() { return authToken; }
    public void setAuthToken(String authToken) { this.authToken = trim(authToken); }
    public String getChannel() { return channel; }
    public void setChannel(String channel) { this.channel = trim(channel); }
    public String getPlatform() { return platform; }
    public void setPlatform(String platform) { this.platform = trim(platform); }
    public String getArch() { return arch; }
    public void setArch(String arch) { this.arch = trim(arch); }
    public String getDeviceId() { return deviceId; }
    public void setDeviceId(String deviceId) { this.deviceId = trim(deviceId); }
    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = trim(userId); }
    public Map<String, Object> getAttributes() { return attributes; }
    public void setAttributes(Map<String, Object> attributes) { this.attributes = attributes == null ? new LinkedHashMap<>() : new LinkedHashMap<>(attributes); }
    public String getPublicKey() { return publicKey; }
    public void setPublicKey(String publicKey) { this.publicKey = trim(publicKey); }
    public boolean isVerifySignature() { return verifySignature; }
    public void setVerifySignature(boolean verifySignature) { this.verifySignature = verifySignature; }
    public int getRetries() { return retries; }
    public void setRetries(int retries) { this.retries = retries; }
    public Duration getBackoff() { return backoff; }
    public void setBackoff(Duration backoff) { this.backoff = backoff; }

    public UpdateCheckResponse checkUpdate(String currentVersion, Integer versionCode) {
        UpdateCheckRequest payload = new UpdateCheckRequest()
                .setChannelCode(channel)
                .setCurrentVersion(currentVersion)
                .setVersionCode(versionCode)
                .setPlatform(platform)
                .setArch(arch)
                .setDeviceId(deviceId)
                .setUserId(userId)
                .setAttributes(attributes);
        UpdateCheckResponse response = parseJson(doRequest("POST", "/api/client/update-check", jsonBytes(payload), "application/json"), UpdateCheckResponse.class);
        verifyUpdateSignature(response);
        return response;
    }

    public void reportEvent(String eventName, Map<String, Object> props) {
        Event payload = new Event()
                .setDeviceId(deviceId)
                .setEventName(eventName)
                .setEventTime(Instant.now())
                .setChannelCode(channel)
                .setProperties(props == null ? new LinkedHashMap<>() : props)
                .setAttributes(attributes);
        doRequest("POST", "/api/client/events", jsonBytes(payload), "application/json");
    }

    public void reportHeartbeat(String appVersion) {
        if (isBlank(deviceId)) {
            throw new SwmValidationException(400, null, "device_id required");
        }
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("device_id", deviceId);
        putIfNotBlank(payload, "channel_code", channel);
        putIfNotBlank(payload, "app_version", appVersion);
        putIfNotBlank(payload, "platform", platform);
        putIfNotBlank(payload, "arch", arch);
        putIfNotBlank(payload, "user_id", userId);
        if (!attributes.isEmpty()) {
            payload.put("attributes", attributes);
        }
        doRequest("POST", "/api/client/heartbeat", jsonBytes(payload), "application/json");
    }

    public void reportEvents(List<Event> events) {
        doRequest("POST", "/api/client/events", jsonBytes(Map.of("events", events)), "application/json");
    }

    public void reportFeedback(String content, Integer rating, String contact, List<String> attachments, Map<String, Object> metadata) {
        if (isBlank(content)) {
            throw new SwmValidationException(400, null, "content required");
        }
        String boundary = "----swm-" + UUID.randomUUID();
        try {
            byte[] body = buildFeedbackMultipart(boundary, content, rating, contact, attachments, metadata);
            doRequest("POST", "/api/client/feedback", body, "multipart/form-data; boundary=" + boundary);
        } catch (IOException e) {
            throw new SwmApiException(0, null, e.getMessage());
        }
    }

    public void download(String url, String destPath, String checksum, String signature, BiConsumer<Long, Long> progress) {
        HttpResponse<InputStream> response = send(HttpRequest.newBuilder(URI.create(url)).GET().build(), HttpResponse.BodyHandlers.ofInputStream());
        if (response.statusCode() >= 300) {
            throw new SwmApiException(response.statusCode(), null, "download failed: " + response.statusCode());
        }
        try {
            Path path = Path.of(destPath);
            if (path.getParent() != null) {
                Files.createDirectories(path.getParent());
            }
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            long total = response.headers().firstValueAsLong("Content-Length").orElse(-1L);
            long written = 0;
            try (InputStream in = response.body(); OutputStream out = Files.newOutputStream(path)) {
                byte[] buffer = new byte[32 * 1024];
                int read;
                while ((read = in.read(buffer)) >= 0) {
                    if (read == 0) {
                        continue;
                    }
                    out.write(buffer, 0, read);
                    digest.update(buffer, 0, read);
                    written += read;
                    if (progress != null) {
                        progress.accept(written, total);
                    }
                }
            }
            if (!isBlank(checksum)) {
                String got = HexFormat.of().formatHex(digest.digest());
                if (!got.equalsIgnoreCase(checksum)) {
                    throw new SwmApiException(0, null, "checksum mismatch: " + got + " != " + checksum);
                }
            }
            if (verifySignature && !isBlank(signature) && !isBlank(checksum)) {
                verifySignature(checksum, signature);
            }
        } catch (IOException | GeneralSecurityException e) {
            throw new SwmApiException(0, null, e.getMessage());
        }
    }

    public UpdateWatchHandle startUpdateStream(UpdateStreamOptions options, Consumer<UpdatePushEvent> onEvent) {
        String resolvedChannel = firstNonBlank(options.getChannelCode(), channel);
        String resolvedPlatform = firstNonBlank(options.getPlatform(), platform);
        String resolvedArch = firstNonBlank(options.getArch(), arch);
        String resolvedDeviceId = firstNonBlank(options.getDeviceId(), deviceId);
        if (isBlank(resolvedChannel) || isBlank(resolvedPlatform) || isBlank(resolvedArch) || isBlank(resolvedDeviceId)) {
            throw new SwmValidationException(400, null, "channel_code/platform/arch/device_id required");
        }
        Thread worker = new Thread(() -> consumeUpdateStream(options, resolvedChannel, resolvedPlatform, resolvedArch, resolvedDeviceId, onEvent), "swm-update-stream");
        worker.setDaemon(true);
        worker.start();
        return new UpdateWatchHandle(worker);
    }

    public UpdateWatchHandle watchUpdates(UpdateStreamOptions options, Consumer<UpdateCheckResponse> onUpdateAvailable) {
        return startUpdateStream(options, evt -> {
            if (CONTROL_EVENT_SHUTDOWN.equalsIgnoreCase(trim(evt.getEventType()))) {
                return;
            }
            try {
                UpdateCheckResponse response = checkUpdate(options.getCurrentVersion(), options.getVersionCode());
                if (response.isUpdateAvailable()) {
                    onUpdateAvailable.accept(response);
                }
            } catch (Throwable ex) {
                if (options.getOnError() != null) {
                    options.getOnError().accept(ex);
                }
            }
        });
    }

    public Map<String, Object> getApp(String appId) { return unwrapObject(authJson("GET", "/api/apps/" + appId, null, null), "app"); }
    public Map<String, Object> updateApp(String appId, Map<String, Object> payload) { return unwrapObject(authJson("PATCH", "/api/apps/" + appId, payload, null), "app"); }
    public List<Map<String, Object>> listChannels(String appId) { return unwrapItems(authJson("GET", "/api/apps/" + appId + "/channels", null, null)); }
    public Map<String, Object> createChannel(String appId, Map<String, Object> payload) { return unwrapObject(authJson("POST", "/api/apps/" + appId + "/channels", payload, null), "channel"); }
    public List<Map<String, Object>> listAppMembers(String appId) { return unwrapItems(authJson("GET", "/api/apps/" + appId + "/members", null, null)); }
    public Map<String, Object> addAppMember(String appId, Map<String, Object> payload) { return parseJson(authJson("POST", "/api/apps/" + appId + "/members", payload, null), MAP_TYPE); }
    public List<Map<String, Object>> listReleases(String appId) { return unwrapItems(authJson("GET", "/api/apps/" + appId + "/releases", null, null)); }
    public Map<String, Object> createRelease(String appId, Map<String, Object> payload) { return unwrapObject(authJson("POST", "/api/apps/" + appId + "/releases", payload, null), "release"); }
    public Map<String, Object> updateRelease(String releaseId, Map<String, Object> payload) { return unwrapObject(authJson("PATCH", "/api/releases/" + releaseId, payload, null), "release"); }
    public void deleteRelease(String releaseId) { authJson("DELETE", "/api/releases/" + releaseId, null, null); }
    public void submitRelease(String releaseId, String note) { reviewReleaseAction(releaseId, "submit", note); }
    public void approveRelease(String releaseId, String note) { reviewReleaseAction(releaseId, "approve", note); }
    public void rejectRelease(String releaseId, String note) { reviewReleaseAction(releaseId, "reject", note); }
    public Map<String, Object> publishRelease(String releaseId, Map<String, Object> payload) { return unwrapObject(authJson("POST", "/api/releases/" + releaseId + "/publish", payload, null), "release_channel"); }
    public Map<String, Object> rollbackRelease(String releaseId, Map<String, Object> payload) { return unwrapObject(authJson("POST", "/api/releases/" + releaseId + "/rollback", payload, null), "release_channel"); }
    public void revokeRelease(String releaseId) { authJson("POST", "/api/releases/" + releaseId + "/revoke", Map.of(), null); }
    public List<Map<String, Object>> listArtifacts(String releaseId) { return unwrapItems(authJson("GET", "/api/releases/" + releaseId + "/artifacts", null, null)); }
    public List<Map<String, Object>> listReleaseChannels(String appId) { return unwrapItems(authJson("GET", "/api/apps/" + appId + "/release-channels", null, null)); }
    public Map<String, Object> createReleaseChannel(String appId, Map<String, Object> payload) { return unwrapObject(authJson("POST", "/api/apps/" + appId + "/release-channels", payload, null), "release_channel"); }
    public Map<String, Object> updateReleaseChannel(String releaseChannelId, Map<String, Object> payload) { return unwrapObject(authJson("PATCH", "/api/release-channels/" + releaseChannelId, payload, null), "release_channel"); }
    public List<Map<String, Object>> listReleaseTemplates() { return unwrapItems(authJson("GET", "/api/release-templates", null, null)); }
    public Map<String, Object> createReleaseTemplate(Map<String, Object> payload) { return unwrapObject(authJson("POST", "/api/release-templates", payload, null), "template"); }
    public Map<String, Object> updateReleaseTemplate(String templateId, Map<String, Object> payload) { return unwrapObject(authJson("PATCH", "/api/release-templates/" + templateId, payload, null), "template"); }
    public void deleteReleaseTemplate(String templateId) { authJson("DELETE", "/api/release-templates/" + templateId, null, null); }
    public Map<String, Object> setReleaseTemplate(String releaseId, String templateId) { return unwrapObject(authJson("PATCH", "/api/releases/" + releaseId + "/template", Map.of("template_id", templateId), null), "release"); }
    public List<Map<String, Object>> listAppSecrets(String appId) { return unwrapItems(authJson("GET", "/api/apps/" + appId + "/app-secrets", null, null)); }
    public AppSecretCreateResponse createAppSecret(String appId, Map<String, Object> payload) { return parseJson(authJson("POST", "/api/apps/" + appId + "/app-secrets", payload, null), AppSecretCreateResponse.class); }
    public void revokeAppSecret(String keyId) { authJson("DELETE", "/api/app-secrets/" + keyId, null, null); }
    public Map<String, Object> listGeoRegions() { return parseJson(authJson("GET", "/api/geo/regions", null, null), MAP_TYPE); }
    public Map<String, Object> resolveGeo(String ip) { return parseJson(authJson("GET", "/api/geo/resolve", null, Map.of("ip", ip)), MAP_TYPE); }

    public Map<String, Object> uploadArtifact(String releaseId, UploadArtifactOptions options) {
        if (isBlank(options.getPlatform()) || isBlank(options.getArch()) || isBlank(options.getFileType())) {
            throw new SwmValidationException(400, null, "platform, arch, file_type required");
        }
        String boundary = "----swm-" + UUID.randomUUID();
        try {
            byte[] body = buildArtifactMultipart(boundary, options);
            return unwrapObject(doAuthRequest("POST", "/api/releases/" + releaseId + "/artifacts", null, body, "multipart/form-data; boundary=" + boundary), "artifact");
        } catch (IOException e) {
            throw new SwmApiException(0, null, e.getMessage());
        }
    }

    public String getArtifactDownloadURL(String artifactId) {
        ensureAuthToken();
        String path = "/api/artifacts/" + artifactId + "/download";
        URI uri = URI.create(baseUrl + path);
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri)
                .GET()
                .header("Authorization", "Bearer " + authToken)
                .timeout(Duration.ofSeconds(30));
        signAuthRequestHeaders(builder, "GET", uri, new byte[0]);
        HttpResponse<Void> response = send(builder.build(), HttpResponse.BodyHandlers.discarding());
        if (response.statusCode() >= 300 && response.statusCode() < 400) {
            return response.headers().firstValue("Location")
                    .orElseThrow(() -> new SwmApiException(response.statusCode(), null, "missing redirect location"));
        }
        throw mapError(response.statusCode(), response.headers(), "");
    }

    public Map<String, Object> getReleaseChannelMetrics(String appId, String releaseChannelId, String from, String to) {
        Map<String, String> query = new LinkedHashMap<>();
        putIfNotBlank(query, "from", from);
        putIfNotBlank(query, "to", to);
        return parseJson(authJson("GET", "/api/apps/" + appId + "/release-channels/" + releaseChannelId + "/metrics", null, query), MAP_TYPE);
    }

    public Object getAppRegionRules(String appId) {
        return unwrapValue(authJson("GET", "/api/apps/" + appId + "/region-rules", null, null), "region_rules");
    }

    public Object updateAppRegionRules(String appId, Object rules) {
        return unwrapValue(authJson("PATCH", "/api/apps/" + appId + "/region-rules", Map.of("region_rules", rules), null), "region_rules");
    }

    private void consumeUpdateStream(UpdateStreamOptions options, String channelCode, String platform, String arch, String deviceId, Consumer<UpdatePushEvent> onEvent) {
        Duration currentBackoff = positiveDuration(options.getReconnectBackoff(), Duration.ofMillis(1500));
        Duration maxBackoff = positiveDuration(options.getReconnectMaxBackoff(), Duration.ofSeconds(20));
        if (maxBackoff.compareTo(currentBackoff) < 0) {
            maxBackoff = currentBackoff;
        }
        while (!Thread.currentThread().isInterrupted()) {
            try {
                connectAndReadSse(options, channelCode, platform, arch, deviceId, onEvent);
                return;
            } catch (Throwable ex) {
                if (options.getOnError() != null) {
                    options.getOnError().accept(ex);
                }
                if (ex instanceof SwmDeviceBlockedException || ex instanceof SwmUpdateRegionBlockedException || ex instanceof SwmUnauthorizedException || !options.isReconnect()) {
                    return;
                }
                sleepWithBackoff(currentBackoff, options.isJitter());
                currentBackoff = currentBackoff.multipliedBy(2);
                if (currentBackoff.compareTo(maxBackoff) > 0) {
                    currentBackoff = maxBackoff;
                }
            }
        }
    }

    private String doRequest(String method, String path, byte[] body, String contentType) {
        if (isBlank(appId) || isBlank(appSecret)) {
            throw new SwmValidationException(400, null, "app_id and app_secret required");
        }
        byte[] payload = body == null ? new byte[0] : body;
        RuntimeException last = null;
        for (int attempt = 0; attempt <= retries; attempt++) {
            try {
                URI uri = URI.create(baseUrl + path);
                HttpRequest.Builder builder = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(30));
                applyBody(builder, method, payload, contentType);
                signClientRequestHeaders(builder, method, uri, payload);
                HttpResponse<String> resp = send(builder.build(), HttpResponse.BodyHandlers.ofString());
                if (resp.statusCode() >= 300) {
                    throw mapError(resp.statusCode(), resp.headers(), resp.body());
                }
                return resp.body();
            } catch (SwmApiException ex) {
                throw ex;
            } catch (RuntimeException ex) {
                last = ex;
                sleepWithBackoff(backoffFor(attempt), false);
            }
        }
        throw last != null ? last : new SwmApiException(0, null, "request failed");
    }

    private String doAuthRequest(String method, String path, Map<String, String> query, byte[] body, String contentType) {
        ensureAuthToken();
        String fullPath = baseUrl + path;
        String qs = buildQueryString(query);
        if (!qs.isEmpty()) {
            fullPath += "?" + qs;
        }
        byte[] payload = body == null ? new byte[0] : body;
        RuntimeException last = null;
        for (int attempt = 0; attempt <= retries; attempt++) {
            try {
                URI uri = URI.create(fullPath);
                HttpRequest.Builder builder = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(30));
                builder.header("Authorization", "Bearer " + authToken);
                applyBody(builder, method, payload, contentType);
                signAuthRequestHeaders(builder, method, uri, payload);
                HttpResponse<String> resp = send(builder.build(), HttpResponse.BodyHandlers.ofString());
                if (resp.statusCode() >= 300) {
                    throw mapError(resp.statusCode(), resp.headers(), resp.body());
                }
                return resp.body();
            } catch (SwmApiException ex) {
                throw ex;
            } catch (RuntimeException ex) {
                last = ex;
                sleepWithBackoff(backoffFor(attempt), false);
            }
        }
        throw last != null ? last : new SwmApiException(0, null, "request failed");
    }

    private String authJson(String method, String path, Object payload, Map<String, String> query) {
        byte[] body = payload == null ? null : jsonBytes(payload);
        String contentType = payload == null ? null : "application/json";
        return doAuthRequest(method, path, query, body, contentType);
    }

    private void reviewReleaseAction(String releaseId, String action, String note) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("note", note);
        authJson("POST", "/api/releases/" + releaseId + "/" + action, payload, null);
    }

    private void applyBody(HttpRequest.Builder builder, String method, byte[] body, String contentType) {
        HttpRequest.BodyPublisher publisher = (body == null || body.length == 0)
                ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofByteArray(body);
        builder.method(method.toUpperCase(), publisher);
        if (contentType != null && body != null && body.length > 0) {
            builder.header("Content-Type", contentType);
        }
    }

    private <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> handler) {
        try {
            return httpClient.send(request, handler);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }
    }

    private void ensureAuthToken() {
        if (isBlank(authToken)) {
            throw new SwmUnauthorizedException(401, null, "auth token required, call setAuthToken first");
        }
    }

    private Duration backoffFor(int attempt) {
        return Duration.ofMillis((long) (backoff.toMillis() * Math.pow(2, attempt)));
    }

    private void signClientRequestHeaders(HttpRequest.Builder builder, String method, URI uri, byte[] body) {
        long timestamp = Instant.now().getEpochSecond();
        String nonce = UUID.randomUUID().toString();
        String canonical = buildCanonical(method, uri, body, timestamp, nonce, appId);
        String signature = hmacSha256Hex(appSecret, canonical);
        builder.header(SIGN_HEADER_APP_ID, appId);
        builder.header(SIGN_HEADER_TIMESTAMP, Long.toString(timestamp));
        builder.header(SIGN_HEADER_NONCE, nonce);
        builder.header(SIGN_HEADER_SIGNATURE, signature);
        builder.header(SIGN_HEADER_VERSION, SIGN_VERSION_V1);
    }

    private void signAuthRequestHeaders(HttpRequest.Builder builder, String method, URI uri, byte[] body) {
        String sub = extractJwtSubject(authToken);
        if (isBlank(sub)) {
            throw new SwmUnauthorizedException(401, null, "invalid auth token subject");
        }
        long timestamp = Instant.now().getEpochSecond();
        String nonce = UUID.randomUUID().toString();
        String canonical = buildCanonical(method, uri, body, timestamp, nonce, sub);
        String signature = hmacSha256Hex(authToken, canonical);
        builder.header(SIGN_HEADER_TIMESTAMP, Long.toString(timestamp));
        builder.header(SIGN_HEADER_NONCE, nonce);
        builder.header(SIGN_HEADER_SIGNATURE, signature);
        builder.header(SIGN_HEADER_VERSION, SIGN_VERSION_V1);
    }

    private String buildCanonical(String method, URI uri, byte[] body, long timestamp, String nonce, String identity) {
        String path = uri.getPath() == null ? "" : uri.getPath();
        return String.join("\n",
                method.toUpperCase(),
                path,
                buildCanonicalQuery(uri.getRawQuery()),
                sha256Hex(body),
                Long.toString(timestamp),
                nonce,
                identity == null ? "" : identity);
    }

    private static String buildCanonicalQuery(String rawQuery) {
        if (isBlank(rawQuery)) {
            return "";
        }
        String raw = rawQuery.startsWith("?") ? rawQuery.substring(1) : rawQuery;
        if (raw.isEmpty()) {
            return "";
        }
        List<String[]> pairs = new ArrayList<>();
        for (String item : raw.split("&")) {
            if (item.isEmpty()) {
                continue;
            }
            int idx = item.indexOf('=');
            String key = idx >= 0 ? item.substring(0, idx) : item;
            String value = idx >= 0 ? item.substring(idx + 1) : "";
            key = urlDecode(key.replace("+", "%20"));
            value = urlDecode(value.replace("+", "%20"));
            pairs.add(new String[]{key, value});
        }
        pairs.sort((a, b) -> {
            int cmp = a[0].compareTo(b[0]);
            return cmp != 0 ? cmp : a[1].compareTo(b[1]);
        });
        List<String> parts = new ArrayList<>();
        for (String[] pair : pairs) {
            parts.add(queryEscapeRfc3986(pair[0]) + "=" + queryEscapeRfc3986(pair[1]));
        }
        return String.join("&", parts);
    }

    private static String buildQueryString(Map<String, String> query) {
        if (query == null || query.isEmpty()) {
            return "";
        }
        List<String> parts = new ArrayList<>();
        for (Map.Entry<String, String> entry : query.entrySet()) {
            if (isBlank(entry.getValue())) {
                continue;
            }
            parts.add(queryEscapeRfc3986(entry.getKey()) + "=" + queryEscapeRfc3986(entry.getValue()));
        }
        return String.join("&", parts);
    }

    private static String queryEscapeRfc3986(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20").replace("*", "%2A");
    }

    private static String urlDecode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    private static String sha256Hex(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(data == null ? new byte[0] : data));
        } catch (GeneralSecurityException e) {
            throw new SwmApiException(0, null, e.getMessage());
        }
    }

    private static String hmacSha256Hex(String key, String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new SwmApiException(0, null, e.getMessage());
        }
    }

    private static String extractJwtSubject(String token) {
        if (isBlank(token)) {
            return "";
        }
        String[] parts = token.split("\\.");
        if (parts.length < 2 || isBlank(parts[1])) {
            return "";
        }
        try {
            byte[] bytes = Base64.getUrlDecoder().decode(padBase64(parts[1].trim()));
            JsonNode node = MAPPER.readTree(bytes);
            if (node.hasNonNull("sub")) {
                return node.get("sub").asText().trim();
            }
            if (node.hasNonNull("uid")) {
                return node.get("uid").asText().trim();
            }
        } catch (Exception ignore) {
            // ignore malformed token
        }
        return "";
    }

    private static String padBase64(String segment) {
        switch (segment.length() % 4) {
            case 2:
                return segment + "==";
            case 3:
                return segment + "=";
            default:
                return segment;
        }
    }

    private RuntimeException mapError(int statusCode, HttpHeaders headers, String body) {
        String code = null;
        String message = "request failed: " + statusCode;
        if (!isBlank(body)) {
            try {
                JsonNode root = MAPPER.readTree(body);
                JsonNode err = root.get("error");
                if (err != null && err.isObject()) {
                    if (err.hasNonNull("code")) {
                        code = err.get("code").asText();
                    }
                    if (err.hasNonNull("message")) {
                        message = err.get("message").asText();
                    } else if (!isBlank(code)) {
                        message = code;
                    }
                } else if (err != null && err.isTextual()) {
                    message = err.asText();
                    code = err.asText();
                } else {
                    message = body;
                }
            } catch (Exception ignore) {
                message = body;
            }
        }
        if (API_ERROR_CODE_DEVICE_BLOCKED.equalsIgnoreCase(safeTrim(code))) {
            return new SwmDeviceBlockedException(statusCode, message);
        }
        if (API_ERROR_CODE_UPDATE_REGION_BLOCKED.equalsIgnoreCase(safeTrim(code))) {
            return new SwmUpdateRegionBlockedException(statusCode, message);
        }
        if (API_ERROR_CODE_FEEDBACK_DISABLED.equalsIgnoreCase(safeTrim(code))) {
            return new SwmFeedbackDisabledException(statusCode, message);
        }
        if (statusCode == 401 || statusCode == 403) {
            return new SwmUnauthorizedException(statusCode, code, message);
        }
        if (statusCode >= 400 && statusCode < 500) {
            return new SwmValidationException(statusCode, code, message);
        }
        return new SwmApiException(statusCode, code, message);
    }

    private byte[] jsonBytes(Object value) {
        try {
            return MAPPER.writeValueAsBytes(value);
        } catch (JsonProcessingException e) {
            throw new SwmApiException(0, null, "failed to encode request: " + e.getMessage());
        }
    }

    private <T> T parseJson(String body, Class<T> type) {
        try {
            return MAPPER.readValue(body, type);
        } catch (IOException e) {
            throw new SwmApiException(0, null, "failed to parse response: " + e.getMessage());
        }
    }

    private <T> T parseJson(String body, TypeReference<T> type) {
        try {
            return MAPPER.readValue(body, type);
        } catch (IOException e) {
            throw new SwmApiException(0, null, "failed to parse response: " + e.getMessage());
        }
    }

    private List<Map<String, Object>> unwrapItems(String body) {
        Map<String, Object> root = parseJson(body, MAP_TYPE);
        Object items = root.get("items");
        List<Map<String, Object>> out = new ArrayList<>();
        if (items instanceof List<?>) {
            for (Object item : (List<?>) items) {
                if (item instanceof Map<?, ?>) {
                    out.add(castMap(item));
                }
            }
        }
        return out;
    }

    private Map<String, Object> unwrapObject(String body, String key) {
        Map<String, Object> root = parseJson(body, MAP_TYPE);
        Object value = root.get(key);
        if (value instanceof Map<?, ?>) {
            return castMap(value);
        }
        return new LinkedHashMap<>();
    }

    private Object unwrapValue(String body, String key) {
        Map<String, Object> root = parseJson(body, MAP_TYPE);
        return root.get(key);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> castMap(Object value) {
        return (Map<String, Object>) value;
    }

    private byte[] buildFeedbackMultipart(String boundary, String content, Integer rating, String contact, List<String> attachments, Map<String, Object> metadata) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeFormField(out, boundary, "device_id", deviceId);
        if (!isBlank(channel)) {
            writeFormField(out, boundary, "channel_code", channel);
        }
        writeFormField(out, boundary, "content", content);
        if (rating != null) {
            writeFormField(out, boundary, "rating", Integer.toString(rating));
        }
        if (!isBlank(contact)) {
            writeFormField(out, boundary, "contact", contact);
        }
        Map<String, Object> merged = new LinkedHashMap<>();
        if (metadata != null) {
            merged.putAll(metadata);
        }
        if (!attributes.isEmpty() && !merged.containsKey("attributes")) {
            merged.put("attributes", attributes);
        }
        if (!merged.isEmpty()) {
            writeFormField(out, boundary, "metadata", new String(jsonBytes(merged), StandardCharsets.UTF_8));
            Object appVersion = merged.get("app_version");
            if (appVersion != null) {
                writeFormField(out, boundary, "app_version", String.valueOf(appVersion));
            }
        }
        if (attachments != null) {
            for (String filePath : attachments) {
                if (isBlank(filePath)) {
                    continue;
                }
                Path path = Path.of(filePath);
                if (!Files.exists(path)) {
                    continue;
                }
                writeFileField(out, boundary, "attachments", path);
            }
        }
        writeMultipartEnd(out, boundary);
        return out.toByteArray();
    }

    private byte[] buildArtifactMultipart(String boundary, UploadArtifactOptions options) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeFormField(out, boundary, "platform", options.getPlatform());
        writeFormField(out, boundary, "arch", options.getArch());
        writeFormField(out, boundary, "file_type", options.getFileType());
        if (!isBlank(options.getSignature())) {
            writeFormField(out, boundary, "signature", options.getSignature());
        }
        if (options.isReplace()) {
            writeFormField(out, boundary, "replace", "true");
        }
        if (isBlank(options.getFilePath())) {
            throw new SwmValidationException(400, null, "file_path required");
        }
        Path filePath = Path.of(options.getFilePath());
        if (!Files.exists(filePath)) {
            throw new SwmValidationException(400, null, "file_path required");
        }
        writeFileField(out, boundary, "file", filePath);
        writeMultipartEnd(out, boundary);
        return out.toByteArray();
    }

    private static void writeFormField(ByteArrayOutputStream out, String boundary, String name, String value) throws IOException {
        out.write(("--" + boundary + "\r\n").getBytes(StandardCharsets.UTF_8));
        out.write(("Content-Disposition: form-data; name=\"" + name + "\"\r\n\r\n").getBytes(StandardCharsets.UTF_8));
        out.write((value == null ? "" : value).getBytes(StandardCharsets.UTF_8));
        out.write("\r\n".getBytes(StandardCharsets.UTF_8));
    }

    private static void writeFileField(ByteArrayOutputStream out, String boundary, String name, Path path) throws IOException {
        String fileName = path.getFileName() == null ? "file" : path.getFileName().toString();
        out.write(("--" + boundary + "\r\n").getBytes(StandardCharsets.UTF_8));
        out.write(("Content-Disposition: form-data; name=\"" + name + "\"; filename=\"" + fileName + "\"\r\n").getBytes(StandardCharsets.UTF_8));
        out.write("Content-Type: application/octet-stream\r\n\r\n".getBytes(StandardCharsets.UTF_8));
        out.write(Files.readAllBytes(path));
        out.write("\r\n".getBytes(StandardCharsets.UTF_8));
    }

    private static void writeMultipartEnd(ByteArrayOutputStream out, String boundary) throws IOException {
        out.write(("--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8));
    }

    private void verifyUpdateSignature(UpdateCheckResponse response) {
        if (response == null || !verifySignature) {
            return;
        }
        String signature = response.getSignature();
        String checksum = response.getChecksumSha256();
        if (isBlank(signature) || isBlank(checksum)) {
            return;
        }
        verifySignature(checksum, signature);
    }

    private void verifySignature(String checksumHex, String signature) {
        if (isBlank(publicKey)) {
            return;
        }
        byte[] publicKeyBytes = decodeBase64OrHex(publicKey);
        byte[] signatureBytes = decodeBase64OrHex(signature);
        byte[] messageBytes = checksumHex.getBytes(StandardCharsets.UTF_8);
        try {
            Ed25519Signer verifier = new Ed25519Signer();
            verifier.init(false, new Ed25519PublicKeyParameters(publicKeyBytes, 0));
            verifier.update(messageBytes, 0, messageBytes.length);
            if (!verifier.verifySignature(signatureBytes)) {
                throw new SwmApiException(0, null, "signature verification failed");
            }
        } catch (SwmApiException ex) {
            throw ex;
        } catch (RuntimeException ex) {
            throw new SwmApiException(0, null, "invalid ed25519 verification parameters: " + ex.getMessage());
        }
    }

    private static byte[] decodeBase64OrHex(String input) {
        if (isBlank(input)) {
            throw new SwmApiException(0, null, "empty key");
        }
        String value = input.trim();
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException ignore) {
            // not base64, fall through to hex
        }
        if (value.length() % 2 != 0) {
            throw new SwmApiException(0, null, "invalid key encoding");
        }
        try {
            return HexFormat.of().parseHex(value);
        } catch (IllegalArgumentException e) {
            throw new SwmApiException(0, null, "invalid key encoding");
        }
    }

    private void connectAndReadSse(UpdateStreamOptions options, String channelCode, String platformValue, String archValue, String deviceIdValue, Consumer<UpdatePushEvent> onEvent) {
        Map<String, String> query = new LinkedHashMap<>();
        query.put("device_id", deviceIdValue);
        query.put("channel_code", channelCode);
        query.put("platform", platformValue);
        query.put("arch", archValue);
        putIfNotBlank(query, "current_version", options.getCurrentVersion());
        if (options.getVersionCode() != null) {
            query.put("version_code", String.valueOf(options.getVersionCode()));
        }
        String qs = buildQueryString(query);
        String url = baseUrl + "/api/client/updates/stream" + (qs.isEmpty() ? "" : "?" + qs);
        URI uri = URI.create(url);
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri)
                .GET()
                .header("Accept", "text/event-stream")
                .timeout(Duration.ofMinutes(60));
        signClientRequestHeaders(builder, "GET", uri, new byte[0]);
        HttpResponse<InputStream> resp = send(builder.build(), HttpResponse.BodyHandlers.ofInputStream());
        if (resp.statusCode() >= 300) {
            throw mapError(resp.statusCode(), resp.headers(), readErrorBody(resp.body()));
        }
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(resp.body(), StandardCharsets.UTF_8))) {
            String eventName = "";
            String eventId = "";
            StringBuilder data = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                if (Thread.currentThread().isInterrupted()) {
                    break;
                }
                if (line.startsWith(":")) {
                    continue;
                }
                if (line.isEmpty()) {
                    flushSseMessage(options, eventName, eventId, data.toString(), onEvent);
                    eventName = "";
                    eventId = "";
                    data.setLength(0);
                    continue;
                }
                if (startsWithIgnoreCase(line, "event:")) {
                    eventName = line.substring(6).trim();
                } else if (startsWithIgnoreCase(line, "id:")) {
                    eventId = line.substring(3).trim();
                } else if (startsWithIgnoreCase(line, "data:")) {
                    if (data.length() > 0) {
                        data.append('\n');
                    }
                    data.append(line.substring(5).trim());
                }
            }
        } catch (IOException e) {
            throw new SwmApiException(0, null, e.getMessage());
        }
    }

    private void flushSseMessage(UpdateStreamOptions options, String eventName, String eventId, String data, Consumer<UpdatePushEvent> onEvent) {
        if (isBlank(data) || "connected".equalsIgnoreCase(eventName)) {
            return;
        }
        UpdatePushEvent event;
        try {
            event = MAPPER.readValue(data, UpdatePushEvent.class);
        } catch (IOException e) {
            return;
        }
        if (event == null) {
            return;
        }
        if (isBlank(event.getId())) {
            event.setId(eventId);
        }
        if (isBlank(event.getEventType())) {
            event.setEventType(eventName);
        }
        Consumer<ControlEvent> onControl = options == null ? null : options.getOnControlEvent();
        if (onControl != null) {
            String type = trim(event.getEventType());
            if (CONTROL_EVENT_SHUTDOWN.equalsIgnoreCase(type)) {
                onControl.accept(new ControlEvent()
                        .setType(CONTROL_EVENT_SHUTDOWN)
                        .setDeviceId(event.getDeviceId())
                        .setReason(event.getReason()));
            } else if (CONTROL_EVENT_MAINTENANCE_SCHEDULED.equalsIgnoreCase(type)
                    || CONTROL_EVENT_MAINTENANCE_CANCELLED.equalsIgnoreCase(type)) {
                onControl.accept(new ControlEvent()
                        .setType(type)
                        .setReason(event.getReason())
                        .setMessage(event.getMessage())
                        .setStartAt(event.getMaintenanceStartAt()));
            }
        }
        onEvent.accept(event);
    }

    private static String readErrorBody(InputStream in) {
        if (in == null) {
            return "";
        }
        try {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            return "";
        }
    }

    private void sleepWithBackoff(Duration duration, boolean jitter) {
        long millis = Math.max(0, duration.toMillis());
        if (jitter && millis > 0) {
            millis += ThreadLocalRandom.current().nextLong(0, Math.max(1, millis / 2));
        }
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static Duration positiveDuration(Duration value, Duration fallback) {
        return (value != null && !value.isZero() && !value.isNegative()) ? value : fallback;
    }

    private static boolean startsWithIgnoreCase(String value, String prefix) {
        return value.regionMatches(true, 0, prefix, 0, prefix.length());
    }

    private static void putIfNotBlank(Map<String, ? super String> map, String key, String value) {
        if (!isBlank(value)) {
            map.put(key, value);
        }
    }

    private static String firstNonBlank(String a, String b) {
        if (!isBlank(a)) {
            return a;
        }
        return b == null ? "" : b;
    }

    private static String trim(String value) {
        return value == null ? "" : value.trim();
    }

    private static String safeTrim(String value) {
        return value == null ? "" : value.trim();
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    private static String trimTrailingSlash(String value) {
        if (value == null) {
            return "";
        }
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }
}
