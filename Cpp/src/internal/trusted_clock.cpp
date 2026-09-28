#include "internal/trusted_clock.hpp"

#include "swm/error.hpp"

#include <windows.h>

#include <mutex>

namespace swm::internal {
namespace {

constexpr std::uint64_t maximum_round_trip_ms = 5000;
constexpr std::int64_t minimum_server_time_ms = 1577836800000LL;
constexpr std::int64_t maximum_server_time_ms = 4102444800000LL;

struct ClockState {
    std::mutex mutex;
    bool initialized = false;
    std::int64_t anchor_unix_ms = 0;
    std::uint64_t anchor_tick_ms = 0;
};

ClockState& state() {
    static ClockState value;
    return value;
}

} // namespace

bool TrustedClock::initialized() const noexcept {
    auto& value = state();
    std::lock_guard lock(value.mutex);
    return value.initialized;
}

std::int64_t TrustedClock::now_unix_ms() const noexcept {
    auto& value = state();
    std::lock_guard lock(value.mutex);
    if (!value.initialized) {
        return 0;
    }
    const auto tick = tick_ms();
    if (tick < value.anchor_tick_ms) {
        return 0;
    }
    return value.anchor_unix_ms + static_cast<std::int64_t>(tick - value.anchor_tick_ms);
}

std::int64_t TrustedClock::now_unix_seconds() const noexcept {
    const auto milliseconds = now_unix_ms();
    return milliseconds <= 0 ? 0 : milliseconds / 1000;
}

void TrustedClock::set_authoritative_time(const std::int64_t server_time_ms,
    const std::uint64_t request_started_tick_ms,
    const std::uint64_t response_received_tick_ms) {
    if (server_time_ms < minimum_server_time_ms || server_time_ms > maximum_server_time_ms ||
        response_received_tick_ms < request_started_tick_ms) {
        throw Error(ErrorKind::Clock, 0, {}, "signed server time is outside the accepted range");
    }
    const auto round_trip = response_received_tick_ms - request_started_tick_ms;
    if (round_trip > maximum_round_trip_ms) {
        throw Error(ErrorKind::Clock, 0, {}, "signed server time round trip is too slow");
    }
    auto& value = state();
    std::lock_guard lock(value.mutex);
    value.anchor_unix_ms = server_time_ms + static_cast<std::int64_t>(round_trip / 2);
    value.anchor_tick_ms = response_received_tick_ms;
    value.initialized = true;
}

std::uint64_t TrustedClock::tick_ms() noexcept {
    return GetTickCount64();
}

} // namespace swm::internal
