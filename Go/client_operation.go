package swm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
)

type operationAuthorizationWireRequest struct {
	Schema                  string `json:"schema"`
	Operation               string `json:"operation"`
	PlanSHA256              string `json:"plan_sha256"`
	StepCount               uint32 `json:"step_count"`
	TotalBytes              uint64 `json:"total_bytes"`
	ConsumerChallenge       string `json:"consumer_challenge"`
	IntegrityManifestSHA256 string `json:"integrity_manifest_sha256,omitempty"`
	HostExeSHA256           string `json:"host_exe_sha256,omitempty"`
	ConsumerModule          string `json:"consumer_module"`
	ConsumerModuleSHA256    string `json:"consumer_module_sha256,omitempty"`
}

type operationConsumeWireRequest struct {
	Schema                  string `json:"schema"`
	GrantID                 string `json:"grant_id"`
	Operation               string `json:"operation"`
	PlanSHA256              string `json:"plan_sha256"`
	StepCount               uint32 `json:"step_count"`
	TotalBytes              uint64 `json:"total_bytes"`
	ConsumerChallenge       string `json:"consumer_challenge"`
	IssuedAt                int64  `json:"issued_at"`
	ExpiresAt               int64  `json:"expires_at"`
	IntegrityManifestSHA256 string `json:"integrity_manifest_sha256,omitempty"`
	HostExeSHA256           string `json:"host_exe_sha256,omitempty"`
	ConsumerModule          string `json:"consumer_module"`
	ConsumerModuleSHA256    string `json:"consumer_module_sha256,omitempty"`
}

// AuthorizeOperation issues a signed Operation Authorization v3 grant.
func (c *Client) AuthorizeOperation(
	ctx context.Context,
	request OperationAuthorizationRequest,
) (OperationGrant, error) {
	if err := c.checkOpen(); err != nil {
		return OperationGrant{}, err
	}
	if c.isOfflineBudgetLocked() {
		return OperationGrant{}, newError(
			KindOfflineBudget, "operation authorization", "offline_budget_exceeded",
			"offline budget exceeded; restart the client and complete a full bootstrap")
	}
	request.Operation = strings.TrimSpace(request.Operation)
	request.ConsumerModule = strings.TrimSpace(request.ConsumerModule)
	if request.Operation == "" {
		return OperationGrant{}, newError(KindValidation, "operation authorization", "operation_required", "operation is required")
	}
	if len(request.Plan) == 0 {
		return OperationGrant{}, newError(KindValidation, "operation authorization", "operation_plan_required", "operation plan is required")
	}
	if request.StepCount == 0 || request.StepCount > 100000 {
		return OperationGrant{}, newError(KindValidation, "operation authorization", "operation_steps_invalid", "step_count must be between 1 and 100000")
	}
	if request.ConsumerModule == "" {
		return OperationGrant{}, newError(KindValidation, "operation authorization", "operation_consumer_required", "consumer_module is required")
	}
	hasHostPath := strings.TrimSpace(request.HostExecutablePath) != ""
	hasModulePath := strings.TrimSpace(request.ConsumerModulePath) != ""
	if hasHostPath != hasModulePath {
		return OperationGrant{}, newError(
			KindValidation, "operation authorization", "operation_paths_incomplete",
			"HostExecutablePath and ConsumerModulePath must be provided together")
	}
	hostBound := hasHostPath || c.hostIntegrityRequired()
	if hostBound && !hasHostPath {
		return OperationGrant{}, newError(
			KindValidation, "operation authorization", "operation_paths_required",
			"host-bound operation authorization requires HostExecutablePath and ConsumerModulePath")
	}
	challenge := append([]byte(nil), request.ConsumerChallenge...)
	if len(challenge) == 0 {
		var err error
		challenge, err = randomBytes(32)
		if err != nil {
			return OperationGrant{}, err
		}
	}
	if len(challenge) != 32 {
		return OperationGrant{}, newError(KindValidation, "operation authorization", "operation_challenge_invalid", "ConsumerChallenge must contain exactly 32 bytes")
	}
	var manifestSHA, hostHash, moduleHash string
	if hostBound {
		evidence, err := c.host.getRequiredEvidence(ctx)
		if err != nil {
			return OperationGrant{}, err
		}
		manifestSHA = evidence.ManifestSHA256
		if manifestSHA == "" {
			return OperationGrant{}, newError(
				KindIntegrity, "operation authorization", "host_manifest_missing",
				"host integrity manifest is unavailable")
		}
		hostHash, moduleHash, err = c.host.resolveOperationHashes(
			request.HostExecutablePath,
			request.ConsumerModulePath,
			ctx,
		)
		if err != nil {
			return OperationGrant{}, err
		}
	}
	schema := "operation_grant_v3_unbound"
	if hostBound {
		schema = "operation_grant_v3_host"
	}
	payload := operationAuthorizationWireRequest{
		Schema:                  schema,
		Operation:               request.Operation,
		PlanSHA256:              sha256Hex(request.Plan),
		StepCount:               request.StepCount,
		TotalBytes:              request.TotalBytes,
		ConsumerChallenge:       hex.EncodeToString(challenge),
		IntegrityManifestSHA256: manifestSHA,
		HostExeSHA256:           hostHash,
		ConsumerModule:          request.ConsumerModule,
		ConsumerModuleSHA256:    moduleHash,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return OperationGrant{}, wrapError(KindProtocol, "operation authorization", err)
	}
	var grant OperationGrant
	if err := c.sendAndVerify(ctx, protocolRequest{
		operation:          opOperationAuthorization,
		method:             http.MethodPost,
		path:               "/api/client/operation-authorizations",
		body:               body,
		encryptBody:        true,
		requireSession:     true,
		requireTrustedTime: true,
		requireOnlineKey:   true,
	}, &grant); err != nil {
		return OperationGrant{}, err
	}
	return grant, nil
}

// ConsumeOperationAuthorization atomically consumes a grant.
func (c *Client) ConsumeOperationAuthorization(
	ctx context.Context,
	grant OperationGrant,
) (OperationConsumptionReceipt, error) {
	if err := c.checkOpen(); err != nil {
		return OperationConsumptionReceipt{}, err
	}
	if c.isOfflineBudgetLocked() {
		return OperationConsumptionReceipt{}, newError(
			KindOfflineBudget, "operation consumption", "offline_budget_exceeded",
			"offline budget exceeded; restart the client and complete a full bootstrap")
	}
	if (grant.Schema != "operation_grant_v3_host" && grant.Schema != "operation_grant_v3_unbound") ||
		!isUUID(grant.GrantID) ||
		grant.Operation == "" ||
		len(grant.PlanSHA256) != 64 ||
		grant.ConsumerModule == "" ||
		grant.ConsumerChallenge == "" ||
		grant.StepCount == 0 ||
		grant.IssuedAt <= 0 ||
		grant.ExpiresAt <= grant.IssuedAt {
		return OperationConsumptionReceipt{}, newError(
			KindValidation, "operation consumption", "operation_grant_invalid",
			"operation grant is incomplete or invalid")
	}
	payload := operationConsumeWireRequest{
		Schema:                  "operation_grant_consume_v2",
		GrantID:                 grant.GrantID,
		Operation:               grant.Operation,
		PlanSHA256:              grant.PlanSHA256,
		StepCount:               grant.StepCount,
		TotalBytes:              grant.TotalBytes,
		ConsumerChallenge:       grant.ConsumerChallenge,
		IssuedAt:                grant.IssuedAt,
		ExpiresAt:               grant.ExpiresAt,
		IntegrityManifestSHA256: grant.IntegrityManifestSHA256,
		HostExeSHA256:           grant.HostExeSHA256,
		ConsumerModule:          grant.ConsumerModule,
		ConsumerModuleSHA256:    grant.ConsumerModuleSHA256,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return OperationConsumptionReceipt{}, wrapError(KindProtocol, "operation consumption", err)
	}
	var receipt OperationConsumptionReceipt
	if err := c.sendAndVerify(ctx, protocolRequest{
		operation:          opOperationGrantConsume,
		method:             http.MethodPost,
		path:               "/api/client/operation-authorizations/consume",
		body:               body,
		encryptBody:        true,
		requireSession:     true,
		requireTrustedTime: true,
		requireOnlineKey:   true,
	}, &receipt); err != nil {
		return OperationConsumptionReceipt{}, err
	}
	return receipt, nil
}
