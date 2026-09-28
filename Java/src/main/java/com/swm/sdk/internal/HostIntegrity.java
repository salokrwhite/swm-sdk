package com.swm.sdk.internal;

import com.fasterxml.jackson.databind.JsonNode;
import com.swm.sdk.SwmClientOptions;
import com.swm.sdk.SwmException;
import com.swm.sdk.SwmModels;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

public final class HostIntegrity {
    private final SwmClientOptions options;
    private final StateStore store;
    private Rim2.Manifest manifest;
    private Path packageRoot;

    public HostIntegrity(SwmClientOptions options, StateStore store) {
        this.options = options;
        this.store = store;
    }

    public SwmModels.IntegrityEvidence evidence() {
        var setting = options.hostIntegrity();
        var root = packageRoot();
        if (setting.evidenceProvider() != null) {
            var context = new SwmClientOptions.IntegrityEvidenceContext(
                options.appId(), options.releaseId(), options.version(), options.versionCode(),
                options.arch(), root, setting.manifestPath());
            return fromNode(setting.evidenceProvider().evidence(context));
        }
        if (!setting.enabled()) {
            return null;
        }
        try {
            var loaded = loadManifest(root);
            Map<String, String> files = new LinkedHashMap<>();
            for (var file : loaded.files()) {
                var path = safeJoin(root, file.path());
                if (!Files.exists(path)) {
                    continue;
                }
                files.put(file.path(), CryptoUtil.sha256Hex(Files.readAllBytes(path)));
            }
            return new SwmModels.IntegrityEvidence("verified", "", 2,
                loaded.manifestSha256(), files);
        } catch (SwmException exception) {
            return new SwmModels.IntegrityEvidence("failed", exception.serviceCode(),
                null, "", Map.of());
        } catch (IOException exception) {
            return new SwmModels.IntegrityEvidence("failed", "host_file_io_failed",
                null, "", Map.of());
        }
    }

    public SwmModels.IntegrityEvidence requiredEvidence() {
        var evidence = evidence();
        if (evidence != null && "failed".equals(evidence.state())) {
            throw new SwmException.Integrity(0, evidence.failureCode(),
                "host integrity validation failed", "");
        }
        return evidence;
    }

    public String manifestSha256() {
        return manifest == null ? "" : manifest.manifestSha256();
    }

    public String[] resolveOperationHashes(
        SwmModels.OperationAuthorizationRequest request
    ) {
        if (request.hostExecutablePath() == null || request.consumerModulePath() == null) {
            throw new SwmException.Configuration("host and consumer paths are required");
        }
        try {
            return new String[] {
                CryptoUtil.sha256Hex(Files.readAllBytes(request.hostExecutablePath())),
                CryptoUtil.sha256Hex(Files.readAllBytes(request.consumerModulePath()))
            };
        } catch (IOException exception) {
            throw new SwmException.Integrity(0, "host_file_io_failed",
                "cannot hash operation paths", "");
        }
    }

    public boolean readCachedPolicy() {
        var plaintext = store.readProtected("integrity-policy.bin");
        if (plaintext.isEmpty()) {
            return false;
        }
        var lines = new String(plaintext.get(), java.nio.charset.StandardCharsets.UTF_8)
            .split("\n", -1);
        if (lines.length < 5 || !"SwmSdkIntegrityPolicyV1".equals(lines[0])
            || !options.appId().equals(lines[2]) || !options.releaseId().equals(lines[3])
            || !String.valueOf(options.versionCode() == null ? "" : options.versionCode())
                .equals(lines[4])) {
            return false;
        }
        return "1".equals(lines[1]);
    }

    public void storePolicy(boolean required) {
        var text = "SwmSdkIntegrityPolicyV1\n" + (required ? "1" : "0") + "\n"
            + options.appId() + "\n" + options.releaseId() + "\n"
            + (options.versionCode() == null ? "" : options.versionCode()) + "\n"
            + System.currentTimeMillis() + "\n";
        store.writeProtected("integrity-policy.bin",
            text.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private Rim2.Manifest loadManifest(Path root) {
        if (manifest != null && root.equals(packageRoot)) {
            return manifest;
        }
        var path = safeJoin(root, options.hostIntegrity().manifestPath());
        try {
            manifest = Rim2.parseAndVerify(Files.readAllBytes(path), options.appId(),
                options.releaseId(), options.version(), options.versionCode(), options.arch(),
                options.rootTrustKeyId(), options.rootTrustPublicKey());
            packageRoot = root;
            return manifest;
        } catch (IOException exception) {
            throw new SwmException.Integrity(0, "host_manifest_missing",
                "RIM2 manifest is missing", "");
        }
    }

    private Path packageRoot() {
        var configured = options.hostIntegrity().packageRoot();
        return configured == null ? Path.of("").toAbsolutePath() : configured.toAbsolutePath();
    }

    private static Path safeJoin(Path root, String relative) {
        var path = root.resolve(relative).normalize().toAbsolutePath();
        if (!path.startsWith(root.normalize().toAbsolutePath())) {
            throw new SwmException.Integrity(0, "host_unsafe_path",
                "integrity path escapes package root", "");
        }
        return path;
    }

    private static SwmModels.IntegrityEvidence fromNode(JsonNode value) {
        if (value == null || value.isNull()) {
            return null;
        }
        Map<String, String> files = new LinkedHashMap<>();
        var fileNode = value.get("integrity_files");
        if (fileNode != null && fileNode.isObject()) {
            fileNode.fields().forEachRemaining(entry -> {
                if (entry.getValue().isTextual()) {
                    files.put(entry.getKey(), entry.getValue().asText());
                }
            });
        }
        return new SwmModels.IntegrityEvidence(
            JsonUtil.text(value, "integrity_state", false),
            JsonUtil.text(value, "integrity_failure_code", false),
            value.hasNonNull("integrity_evidence_version")
                ? value.get("integrity_evidence_version").intValue() : null,
            JsonUtil.text(value, "integrity_manifest_sha256", false),
            files);
    }
}
