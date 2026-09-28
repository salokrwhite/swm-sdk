#pragma once

#include <stdexcept>
#include <string>
#include <utility>

namespace swm {

enum class ErrorKind {
    Configuration,
    Validation,
    Network,
    Timeout,
    Clock,
    Protocol,
    Cryptographic,
    Identity,
    Unauthorized,
    Session,
    DeviceBlocked,
    UnsupportedVersion,
    UpdateRegionBlocked,
    FeedbackDisabled,
    Integrity,
    OperationAuthorization,
    OfflineBudget,
    RateLimit,
    Api
};

enum class IntegrityFailureAction {
    DenyOperations,
    ShutdownClient
};

class Error final : public std::runtime_error {
public:
    Error(ErrorKind kind, int status_code, std::string service_code,
        std::string message, std::string response_body = {},
        IntegrityFailureAction failure_action = IntegrityFailureAction::ShutdownClient,
        std::string minimum_supported_version = {})
        : std::runtime_error(message),
        kind(kind),
        status_code(status_code),
        service_code(std::move(service_code)),
        response_body(std::move(response_body)),
        failure_action(failure_action),
        minimum_supported_version(std::move(minimum_supported_version)) {}

    ErrorKind kind;
    int status_code = 0;
    std::string service_code;
    std::string response_body;
    IntegrityFailureAction failure_action = IntegrityFailureAction::ShutdownClient;
    std::string minimum_supported_version;
};

} // namespace swm
