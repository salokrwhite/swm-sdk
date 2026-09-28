package swm

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrorKind classifies SDK failures for errors.Is and errors.As checks.
type ErrorKind string

const (
	KindConfiguration          ErrorKind = "configuration"
	KindUnsupportedPlatform    ErrorKind = "unsupported_platform"
	KindNetwork                ErrorKind = "network"
	KindTimeout                ErrorKind = "timeout"
	KindProtocol               ErrorKind = "protocol"
	KindIdentity               ErrorKind = "identity"
	KindCryptographic          ErrorKind = "cryptographic"
	KindClock                  ErrorKind = "clock"
	KindSession                ErrorKind = "session"
	KindUnauthorized           ErrorKind = "unauthorized"
	KindValidation             ErrorKind = "validation"
	KindRateLimit              ErrorKind = "rate_limit"
	KindAPI                    ErrorKind = "api"
	KindDeviceBlocked          ErrorKind = "device_blocked"
	KindUnsupportedVersion     ErrorKind = "unsupported_version"
	KindUpdateRegionBlocked    ErrorKind = "update_region_blocked"
	KindFeedbackDisabled       ErrorKind = "feedback_disabled"
	KindIntegrity              ErrorKind = "integrity"
	KindOperationAuthorization ErrorKind = "operation_authorization"
	KindOfflineBudget          ErrorKind = "offline_budget"
)

// IntegrityFailureAction tells the application how to react to an integrity
// failure reported by the service.
type IntegrityFailureAction string

const (
	IntegrityDenyOperations IntegrityFailureAction = "deny_operations"
	IntegrityShutdownClient IntegrityFailureAction = "shutdown_client"
)

// Error is the common error type returned by the SDK.
type Error struct {
	Kind                    ErrorKind
	Op                      string
	StatusCode              int
	Code                    string
	Message                 string
	ResponseBody            string
	RetryAfter              time.Duration
	FailureAction           IntegrityFailureAction
	MinimumSupportedVersion string
	Err                     error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	var b strings.Builder
	if e.Op != "" {
		b.WriteString(e.Op)
		b.WriteString(": ")
	}
	if e.StatusCode > 0 {
		fmt.Fprintf(&b, "HTTP %d", e.StatusCode)
		if e.Code != "" {
			b.WriteString(" ")
			b.WriteString(e.Code)
		}
		if e.Message != "" {
			b.WriteString(": ")
			b.WriteString(e.Message)
		}
	} else if e.Code != "" {
		b.WriteString(e.Code)
		if e.Message != "" {
			b.WriteString(": ")
			b.WriteString(e.Message)
		}
	} else if e.Message != "" {
		b.WriteString(e.Message)
	} else if e.Err != nil {
		b.WriteString(e.Err.Error())
	} else {
		b.WriteString(string(e.Kind))
	}
	return b.String()
}

// Unwrap exposes the transport or platform cause.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// Is allows errors.Is to match SDK error sentinels.
func (e *Error) Is(target error) bool {
	if e == nil {
		return target == nil
	}
	other, ok := target.(*Error)
	if !ok {
		return false
	}
	if e.Kind != other.Kind {
		return false
	}
	return other.Code == "" || e.Code == other.Code
}

var (
	ErrConfiguration          = &Error{Kind: KindConfiguration}
	ErrUnsupportedPlatform    = &Error{Kind: KindUnsupportedPlatform}
	ErrNetwork                = &Error{Kind: KindNetwork}
	ErrTimeout                = &Error{Kind: KindTimeout}
	ErrProtocol               = &Error{Kind: KindProtocol}
	ErrIdentity               = &Error{Kind: KindIdentity}
	ErrCryptographic          = &Error{Kind: KindCryptographic}
	ErrClock                  = &Error{Kind: KindClock}
	ErrSession                = &Error{Kind: KindSession}
	ErrUnauthorized           = &Error{Kind: KindUnauthorized}
	ErrValidation             = &Error{Kind: KindValidation}
	ErrRateLimit              = &Error{Kind: KindRateLimit}
	ErrAPI                    = &Error{Kind: KindAPI}
	ErrDeviceBlocked          = &Error{Kind: KindDeviceBlocked, Code: "device_blocked"}
	ErrUnsupportedVersion     = &Error{Kind: KindUnsupportedVersion, Code: "client_version_unsupported"}
	ErrUpdateRegionBlocked    = &Error{Kind: KindUpdateRegionBlocked, Code: "update_region_blocked"}
	ErrFeedbackDisabled       = &Error{Kind: KindFeedbackDisabled, Code: "feedback_disabled"}
	ErrIntegrity              = &Error{Kind: KindIntegrity}
	ErrOperationAuthorization = &Error{Kind: KindOperationAuthorization}
	ErrOfflineBudget          = &Error{Kind: KindOfflineBudget, Code: "offline_budget_exceeded"}
)

func newError(kind ErrorKind, op, code, message string) *Error {
	return &Error{Kind: kind, Op: op, Code: code, Message: message}
}

func wrapError(kind ErrorKind, op string, err error) *Error {
	if err == nil {
		return nil
	}
	var sdkErr *Error
	if errors.As(err, &sdkErr) {
		return sdkErr
	}
	return &Error{Kind: kind, Op: op, Message: err.Error(), Err: err}
}
