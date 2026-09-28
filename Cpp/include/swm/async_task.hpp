#pragma once

#include <condition_variable>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stop_token>
#include <thread>
#include <type_traits>
#include <utility>
#include <variant>

namespace swm {

namespace detail {

template <typename T>
struct AsyncState final {
    std::mutex mutex;
    std::condition_variable condition;
    std::conditional_t<std::is_void_v<T>, std::monostate, std::optional<T>> value;
    std::exception_ptr exception;
    std::function<void()> completed;
    std::function<void(const std::exception_ptr&)> failed;
    bool done = false;
    std::jthread worker;
};

} // namespace detail

template <typename T>
class AsyncTask final {
public:
    AsyncTask() = default;

    void cancel() noexcept {
        if (state_) {
            state_->worker.request_stop();
        }
    }

    [[nodiscard]] bool valid() const noexcept { return static_cast<bool>(state_); }

    T wait() {
        if (!state_) {
            throw std::logic_error("AsyncTask is not valid");
        }
        std::unique_lock lock(state_->mutex);
        state_->condition.wait(lock, [&] { return state_->done; });
        if (state_->exception) {
            std::rethrow_exception(state_->exception);
        }
        if (!state_->value) {
            throw std::logic_error("AsyncTask completed without a value");
        }
        return *state_->value;
    }

    void on_completed(std::function<void()> callback) {
        if (!state_) {
            return;
        }
        bool invoke_now = false;
        {
            std::lock_guard lock(state_->mutex);
            if (state_->done && !state_->exception) {
                invoke_now = true;
            } else {
                state_->completed = std::move(callback);
            }
        }
        if (invoke_now && callback) {
            callback();
        }
    }

    void on_error(std::function<void(const std::exception_ptr&)> callback) {
        if (!state_) {
            return;
        }
        bool invoke_now = false;
        {
            std::lock_guard lock(state_->mutex);
            if (state_->done && state_->exception) {
                invoke_now = true;
            } else {
                state_->failed = std::move(callback);
            }
        }
        if (invoke_now && callback) {
            callback(state_->exception);
        }
    }

private:
    template <typename F>
    friend AsyncTask<std::invoke_result_t<std::decay_t<F>, std::stop_token>>
        make_async(F&& function);

    explicit AsyncTask(std::shared_ptr<detail::AsyncState<T>> state) : state_(std::move(state)) {}

    std::shared_ptr<detail::AsyncState<T>> state_;
};

template <>
class AsyncTask<void> final {
public:
    AsyncTask() = default;

    void cancel() noexcept {
        if (state_) {
            state_->worker.request_stop();
        }
    }

    [[nodiscard]] bool valid() const noexcept { return static_cast<bool>(state_); }

    void wait() {
        if (!state_) {
            throw std::logic_error("AsyncTask is not valid");
        }
        std::unique_lock lock(state_->mutex);
        state_->condition.wait(lock, [&] { return state_->done; });
        if (state_->exception) {
            std::rethrow_exception(state_->exception);
        }
    }

    void on_completed(std::function<void()> callback) {
        if (!state_) {
            return;
        }
        bool invoke_now = false;
        {
            std::lock_guard lock(state_->mutex);
            if (state_->done && !state_->exception) {
                invoke_now = true;
            } else {
                state_->completed = std::move(callback);
            }
        }
        if (invoke_now && callback) {
            callback();
        }
    }

    void on_error(std::function<void(const std::exception_ptr&)> callback) {
        if (!state_) {
            return;
        }
        bool invoke_now = false;
        {
            std::lock_guard lock(state_->mutex);
            if (state_->done && state_->exception) {
                invoke_now = true;
            } else {
                state_->failed = std::move(callback);
            }
        }
        if (invoke_now && callback) {
            callback(state_->exception);
        }
    }

private:
    template <typename F>
    friend AsyncTask<std::invoke_result_t<std::decay_t<F>, std::stop_token>>
        make_async(F&& function);

    explicit AsyncTask(std::shared_ptr<detail::AsyncState<void>> state) : state_(std::move(state)) {}

    std::shared_ptr<detail::AsyncState<void>> state_;
};

template <typename F>
auto make_async(F&& function) -> AsyncTask<std::invoke_result_t<std::decay_t<F>, std::stop_token>> {
    using T = std::invoke_result_t<std::decay_t<F>, std::stop_token>;
    auto state = std::make_shared<detail::AsyncState<T>>();
    auto callable = std::forward<F>(function);
    state->worker = std::jthread([state, callable = std::move(callable)](std::stop_token stop) mutable {
        try {
            if constexpr (std::is_void_v<T>) {
                callable(stop);
                {
                    std::lock_guard lock(state->mutex);
                    state->done = true;
                }
            } else {
                T value = callable(stop);
                {
                    std::lock_guard lock(state->mutex);
                    state->value.emplace(std::move(value));
                    state->done = true;
                }
            }
        } catch (...) {
            {
                std::lock_guard lock(state->mutex);
                state->exception = std::current_exception();
                state->done = true;
            }
        }
        state->condition.notify_all();
        std::function<void()> completed;
        std::function<void(const std::exception_ptr&)> failed;
        std::exception_ptr exception;
        {
            std::lock_guard lock(state->mutex);
            completed = std::move(state->completed);
            failed = std::move(state->failed);
            exception = state->exception;
        }
        if (exception && failed) {
            failed(exception);
        } else if (completed) {
            completed();
        }
    });
    return AsyncTask<T>(std::move(state));
}

} // namespace swm
