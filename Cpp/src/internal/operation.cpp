#include "internal/operation.hpp"

#include "internal/common.hpp"

namespace swm::internal {

bool validate_operation_authorization_request(
    const OperationAuthorizationRequest& request,
    const bool host_integrity_required) {
    if (trim_ascii(request.operation).empty() || request.plan.empty() ||
        request.step_count == 0 || request.step_count > 100000 ||
        trim_ascii(request.consumer_module).empty()) {
        throw Error(ErrorKind::Configuration, 0, {},
            "operation authorization request is invalid");
    }
    const bool has_host_path = !request.host_executable_path.empty();
    const bool has_module_path = !request.consumer_module_path.empty();
    if (has_host_path != has_module_path) {
        throw Error(ErrorKind::Configuration, 0, {},
            "host_executable_path and consumer_module_path must be provided together");
    }
    const bool host_bound = has_host_path || host_integrity_required;
    if (host_bound && !has_host_path) {
        throw Error(ErrorKind::Configuration, 0, {},
            "host-bound operation authorization requires host and consumer module paths");
    }
    if (!request.consumer_challenge.empty() && request.consumer_challenge.size() != 32) {
        throw Error(ErrorKind::Configuration, 0, {},
            "consumer challenge must be 32 bytes");
    }
    return host_bound;
}

void validate_operation_grant(const OperationGrant& grant) {
    if ((grant.schema != "operation_grant_v3_host" &&
            grant.schema != "operation_grant_v3_unbound") ||
        grant.grant_id.empty() || grant.operation.empty() || grant.plan_sha256.empty() ||
        grant.consumer_module.empty() || grant.consumer_challenge.empty() ||
        grant.step_count == 0 || grant.issued_at <= 0 || grant.expires_at <= grant.issued_at) {
        throw Error(ErrorKind::Configuration, 0, {},
            "operation grant is incomplete or invalid");
    }
}

} // namespace swm::internal
