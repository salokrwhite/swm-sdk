package com.swm.sdk;

import com.fasterxml.jackson.databind.JsonNode;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

/**
 * Strongly typed protocol models used by the Java SDK.
 */
public final class SwmModels {
    private SwmModels() {}

    public record HardwareEvidence(int version, long componentMask, String aggregateHash) {
        public HardwareEvidence {
            version = version == 0 ? 2 : version;
        }
    }

    public record IntegrityEvidence(
        String state,
        String failureCode,
        Integer evidenceVersion,
        String manifestSha256,
        java.util.Map<String, String> files
    ) {
        public IntegrityEvidence {
            files = files == null ? java.util.Map.of() : java.util.Map.copyOf(files);
        }
    }

    public record MaintenanceInfo(boolean enabled, String startAt, String message, boolean active) {}

    public record UpdateInfo(
        boolean updateAvailable,
        boolean mandatory,
        int heartbeatIntervalSeconds,
        boolean openInBrowser,
        String deliveryMethod,
        String releaseId,
        String version,
        Integer versionCode,
        String notes,
        String downloadUrl,
        String checksumSha256,
        String signature,
        String manifestKeyId,
        String manifestPublicKey,
        String rootTrustKeyId,
        String rootTrustSignature,
        String artifactFileName,
        String artifactPlatform,
        String artifactArch,
        String authzProtocol,
        boolean hostIntegrityRequired,
        long size,
        boolean rollbackAllowed,
        MaintenanceInfo maintenance
    ) {}

    public record HeartbeatResult(boolean ok, String serverTime, MaintenanceInfo maintenance) {}

    public record Event(
        String deviceId,
        String eventName,
        String eventTime,
        String channelCode,
        JsonNode properties,
        JsonNode attributes
    ) {}

    public record FeedbackRequest(
        String content,
        Integer rating,
        String contact,
        String appVersion,
        List<Path> attachments,
        JsonNode metadata
    ) {
        public FeedbackRequest {
            attachments = attachments == null ? List.of() : List.copyOf(attachments);
        }
    }

    public record FeedbackResult(boolean ok, String id) {}

    public record EnrollmentTicket(String ticket, long expiresAt, String audience) {}

    public record DeviceKeyRotationResult(
        String registrationId,
        String installId,
        String keyId,
        String deviceId
    ) {}

    public record OperationAuthorizationRequest(
        String operation,
        byte[] plan,
        int stepCount,
        long totalBytes,
        String consumerModule,
        byte[] consumerChallenge,
        Path hostExecutablePath,
        Path consumerModulePath
    ) {}

    public record OperationGrant(
        String schema,
        String appId,
        String releaseId,
        String deviceId,
        String deviceKeyId,
        String keyThumbprint,
        String devicePublicKey,
        String authzPublicKey,
        String authzKeyId,
        String authzRootTrustKeyId,
        String authzRootTrustSignature,
        String session,
        String grantId,
        String operation,
        String planSha256,
        int stepCount,
        long totalBytes,
        long issuedAt,
        long expiresAt,
        String consumerChallenge,
        String integrityManifestSha256,
        String hostExeSha256,
        String consumerModule,
        String consumerModuleSha256
    ) {}

    public record OperationConsumptionReceipt(
        String schema,
        String grantId,
        String operation,
        String planSha256,
        int stepCount,
        long totalBytes,
        String consumerChallenge,
        long consumedAt,
        long expiresAt,
        String integrityManifestSha256,
        String hostExeSha256,
        String consumerModule,
        String consumerModuleSha256
    ) {}

    public record UpdateEvent(
        String id,
        String eventType,
        String orgId,
        String appId,
        String deviceId,
        String channelCode,
        String platform,
        String arch,
        String releaseId,
        String publishedAt,
        String reason,
        String message,
        String maintenanceStartAt
    ) {}

    public record UpdateStreamOptions(
        String currentVersion,
        Integer versionCode,
        boolean reconnect,
        Duration reconnectBackoff,
        Duration reconnectMaxBackoff,
        boolean jitter
    ) {
        public static UpdateStreamOptions defaults() {
            return new UpdateStreamOptions(
                null, null, true, Duration.ofMillis(1500), Duration.ofSeconds(20), true);
        }
    }

    public record DebugRequestTicket(String requestId, String watchToken, long expiresAt) {}

    public record DebugDecisionEvent(String state, String reason, long authorizationExpiresAt) {}
}
