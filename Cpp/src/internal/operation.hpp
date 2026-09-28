#pragma once

#include "swm/types.hpp"

namespace swm::internal {

[[nodiscard]] bool validate_operation_authorization_request(
    const OperationAuthorizationRequest& request,
    bool host_integrity_required);
void validate_operation_grant(const OperationGrant& grant);

} // namespace swm::internal
