package com.swm.sdk;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Device-bound authorization verdict signed by the server with an Ed25519 key.
 * The client MUST verify it (signature + nonce + device + expiry + decision)
 * before trusting the response. A fake/offline server cannot forge it because
 * the private key never ships with the client.
 */
public final class AuthzEnvelope {
    @JsonProperty("decision")
    private String decision;

    @JsonProperty("nonce")
    private String nonce;

    @JsonProperty("device_id")
    private String deviceId;

    @JsonProperty("issued_at")
    private long issuedAt;

    @JsonProperty("expires_at")
    private long expiresAt;

    @JsonProperty("key_id")
    private String keyId;

    @JsonProperty("reason")
    private String reason;

    @JsonProperty("signature")
    private String signature;

    public String getDecision() { return decision; }
    public AuthzEnvelope setDecision(String decision) { this.decision = decision; return this; }
    public String getNonce() { return nonce; }
    public AuthzEnvelope setNonce(String nonce) { this.nonce = nonce; return this; }
    public String getDeviceId() { return deviceId; }
    public AuthzEnvelope setDeviceId(String deviceId) { this.deviceId = deviceId; return this; }
    public long getIssuedAt() { return issuedAt; }
    public AuthzEnvelope setIssuedAt(long issuedAt) { this.issuedAt = issuedAt; return this; }
    public long getExpiresAt() { return expiresAt; }
    public AuthzEnvelope setExpiresAt(long expiresAt) { this.expiresAt = expiresAt; return this; }
    public String getKeyId() { return keyId; }
    public AuthzEnvelope setKeyId(String keyId) { this.keyId = keyId; return this; }
    public String getReason() { return reason; }
    public AuthzEnvelope setReason(String reason) { this.reason = reason; return this; }
    public String getSignature() { return signature; }
    public AuthzEnvelope setSignature(String signature) { this.signature = signature; return this; }
}
