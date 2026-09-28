package com.swm.sdk;

import com.fasterxml.jackson.databind.JsonNode;

import java.net.URI;
import java.nio.file.Path;
import java.util.Objects;
import java.util.function.Function;

/**
 * Immutable SDK configuration.
 */
public final class SwmClientOptions {
    private final String baseUrl;
    private final String webBaseUrl;
    private final String appId;
    private final String releaseId;
    private final String version;
    private final Integer versionCode;
    private final String rootTrustKeyId;
    private final String rootTrustPublicKey;
    private final String channel;
    private final String platform;
    private final String arch;
    private final String deviceId;
    private final Path storageDirectory;
    private final boolean allowInsecureHttp;
    private final HostIntegrityOptions hostIntegrity;
    private final HttpTransport httpTransport;

    private SwmClientOptions(Builder builder) {
        this.baseUrl = Objects.requireNonNull(builder.baseUrl, "baseUrl");
        this.webBaseUrl = builder.webBaseUrl;
        this.appId = Objects.requireNonNull(builder.appId, "appId");
        this.releaseId = Objects.requireNonNull(builder.releaseId, "releaseId");
        this.version = Objects.requireNonNull(builder.version, "version");
        this.versionCode = builder.versionCode;
        this.rootTrustKeyId = Objects.requireNonNull(builder.rootTrustKeyId, "rootTrustKeyId");
        this.rootTrustPublicKey = Objects.requireNonNull(builder.rootTrustPublicKey, "rootTrustPublicKey");
        this.channel = builder.channel;
        this.platform = builder.platform;
        this.arch = builder.arch == null || builder.arch.isBlank()
            ? (System.getProperty("os.arch", "").contains("86") ? "x86" : "x64")
            : builder.arch;
        this.deviceId = builder.deviceId;
        this.storageDirectory = builder.storageDirectory;
        this.allowInsecureHttp = builder.allowInsecureHttp;
        this.hostIntegrity = builder.hostIntegrity;
        this.httpTransport = builder.httpTransport;
    }

    public static Builder builder() { return new Builder(); }

    public String baseUrl() { return baseUrl; }
    public String webBaseUrl() { return webBaseUrl; }
    public String appId() { return appId; }
    public String releaseId() { return releaseId; }
    public String version() { return version; }
    public Integer versionCode() { return versionCode; }
    public String rootTrustKeyId() { return rootTrustKeyId; }
    public String rootTrustPublicKey() { return rootTrustPublicKey; }
    public String channel() { return channel; }
    public String platform() { return platform; }
    public String arch() { return arch; }
    public String deviceId() { return deviceId; }
    public Path storageDirectory() { return storageDirectory; }
    public boolean allowInsecureHttp() { return allowInsecureHttp; }
    public HostIntegrityOptions hostIntegrity() { return hostIntegrity; }
    public HttpTransport httpTransport() { return httpTransport; }

    public URI baseUri() {
        var uri = URI.create(baseUrl.endsWith("/") ? baseUrl : baseUrl + "/");
        validateHttpUri(uri, "baseUrl");
        return uri;
    }

    public URI webBaseUri() {
        var raw = webBaseUrl == null || webBaseUrl.isBlank() ? baseUrl : webBaseUrl;
        var uri = URI.create(raw.endsWith("/") ? raw : raw + "/");
        validateHttpUri(uri, "webBaseUrl");
        return uri;
    }

    private void validateHttpUri(URI uri, String field) {
        var scheme = uri.getScheme();
        if (scheme == null || (!scheme.equalsIgnoreCase("https")
                && !(allowInsecureHttp && scheme.equalsIgnoreCase("http")))) {
            throw new SwmException.Configuration(field + " must use HTTPS");
        }
    }

    public static final class HostIntegrityOptions {
        private final boolean enabled;
        private final Path packageRoot;
        private final String manifestPath;
        private final IntegrityEvidenceProvider evidenceProvider;

        private HostIntegrityOptions(HostIntegrityBuilder builder) {
            this.enabled = builder.enabled;
            this.packageRoot = builder.packageRoot;
            this.manifestPath = builder.manifestPath;
            this.evidenceProvider = builder.evidenceProvider;
        }

        public static HostIntegrityBuilder builder() {
            return new HostIntegrityBuilder();
        }

        public boolean enabled() { return enabled; }
        public Path packageRoot() { return packageRoot; }
        public String manifestPath() { return manifestPath; }
        public IntegrityEvidenceProvider evidenceProvider() { return evidenceProvider; }
    }

    @FunctionalInterface
    public interface IntegrityEvidenceProvider {
        JsonNode evidence(IntegrityEvidenceContext context);
    }

    public static final class IntegrityEvidenceContext {
        public final String appId;
        public final String releaseId;
        public final String version;
        public final Integer versionCode;
        public final String arch;
        public final Path packageRoot;
        public final String manifestPath;

        public IntegrityEvidenceContext(String appId, String releaseId, String version,
                                        Integer versionCode, String arch, Path packageRoot,
                                        String manifestPath) {
            this.appId = appId;
            this.releaseId = releaseId;
            this.version = version;
            this.versionCode = versionCode;
            this.arch = arch;
            this.packageRoot = packageRoot;
            this.manifestPath = manifestPath;
        }
    }

    public static final class Builder {
        private String baseUrl;
        private String webBaseUrl;
        private String appId;
        private String releaseId;
        private String version;
        private Integer versionCode;
        private String rootTrustKeyId;
        private String rootTrustPublicKey;
        private String channel = "stable";
        private String platform = "windows";
        private String arch;
        private String deviceId;
        private Path storageDirectory;
        private boolean allowInsecureHttp;
        private HostIntegrityOptions hostIntegrity =
            new HostIntegrityOptions(new HostIntegrityBuilder());
        private HttpTransport httpTransport;

        public Builder baseUrl(String value) { this.baseUrl = value; return this; }
        public Builder webBaseUrl(String value) { this.webBaseUrl = value; return this; }
        public Builder appId(String value) { this.appId = value; return this; }
        public Builder releaseId(String value) { this.releaseId = value; return this; }
        public Builder version(String value) { this.version = value; return this; }
        public Builder versionCode(Integer value) { this.versionCode = value; return this; }
        public Builder rootTrustKeyId(String value) { this.rootTrustKeyId = value; return this; }
        public Builder rootTrustPublicKey(String value) { this.rootTrustPublicKey = value; return this; }
        public Builder channel(String value) { this.channel = value; return this; }
        public Builder platform(String value) { this.platform = value; return this; }
        public Builder arch(String value) { this.arch = value; return this; }
        public Builder deviceId(String value) { this.deviceId = value; return this; }
        public Builder storageDirectory(Path value) { this.storageDirectory = value; return this; }
        public Builder allowInsecureHttp(boolean value) { this.allowInsecureHttp = value; return this; }
        public Builder hostIntegrity(HostIntegrityOptions value) { this.hostIntegrity = value; return this; }
        public Builder httpTransport(HttpTransport value) { this.httpTransport = value; return this; }

        public SwmClientOptions build() { return new SwmClientOptions(this); }
    }

    public static final class HostIntegrityBuilder {
        private boolean enabled;
        private Path packageRoot;
        private String manifestPath = "release-integrity.v2";
        private IntegrityEvidenceProvider evidenceProvider;

        public HostIntegrityBuilder enabled(boolean value) { this.enabled = value; return this; }
        public HostIntegrityBuilder packageRoot(Path value) { this.packageRoot = value; return this; }
        public HostIntegrityBuilder manifestPath(String value) { this.manifestPath = value; return this; }
        public HostIntegrityBuilder evidenceProvider(IntegrityEvidenceProvider value) {
            this.evidenceProvider = value;
            return this;
        }
        public HostIntegrityOptions build() { return new HostIntegrityOptions(this); }
    }

}
