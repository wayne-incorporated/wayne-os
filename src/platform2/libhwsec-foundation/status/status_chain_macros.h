// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_STATUS_STATUS_CHAIN_MACROS_H_
#define LIBHWSEC_FOUNDATION_STATUS_STATUS_CHAIN_MACROS_H_

#include <optional>
#include <sstream>
#include <string>
#include <type_traits>
#include <utility>

#include <base/logging.h>

#include "libhwsec-foundation/status/status_chain.h"
#include "libhwsec-foundation/status/status_chain_or.h"

// Convenience macros to use with libhwsec StatusChain.
//
// RETURN_IF_ERROR replaces the need for an explicit check of the returned
// status if the code only needs to wrap it and propagate forward.
//
// The following example can be simplified by using the macro
//
// StatusChain<ErrorType> f() {}
// ...
// if (StatusChain<ErrorType> status = f(); !status.ok()) {
//  return MakeStatus<AnotherErrorType>(args).Wrap(std::move(status));
// }
// ...
// RETURN_IF_ERROR(f()).WithStatus<AnotherErrorType>(args);
//
// If the code only needs to propagate the error without modification:
//
// RETURN_IF_ERROR(f());
//
// if the returned value of the function is not StatusChain, As() use as
// value.
//
// RETURN_IF_ERROR(f()).As(42);
//
// Log* variant prints the error message and status.ToFullString before
// returning.
//
// RETURN_IF_ERROR(f()).LogError() << "some log";
//
// -------------------------------------------------
//
// ASSIGN_OR_RETURN replaces the need for an explicit check of the returned
// status if the code only needs to wrap it and propagate forward, and assigning
// the value.
//
// The following example can be simplified by using the macro
//
// StatusChainOr<int, ErrorType> g() {}
// ...
// StatusChainOr<int, ErrorType> status_or = g();
// if (!status_or.ok()) {
//  return
//  MakeStatus<AnotherErrorType>(args).Wrap(std::move(status_or).status());
// }
// int value = status_or.value();
// ...
// ASSIGN_OR_RETURN(int value, g()).WithStatus<AnotherErrorType>(args);
//
// If the code only needs to propagate the error without modification:
//
// ASSIGN_OR_RETURN(int value, g());
//
// if the returned value of the function is not StatusChain, As() use as
// value.
//
// ASSIGN_OR_RETURN(int value, g()).As(42);
//
// Log* variant prints the error message and status.ToFullString before
// returning.
//
// ASSIGN_OR_RETURN(int value, g()).LogError() << "some log";

#ifdef RETURN_IF_ERROR
#error "RETURN_IF_ERROR is defined in the scope."
#endif

#ifdef ASSIGN_OR_RETURN
#error "ASSIGN_OR_RETURN is defined in the scope."
#endif

namespace hwsec_foundation {
namespace status {

struct StatusLinkerLogDetail {
  const char* file;
  int line;
  std::optional<logging::LogSeverity> severity;
  std::ostringstream stream;
};

template <typename T>
class StatusLinker {
 public:
  StatusLinker(const char* file,
               int line,
               StatusChain<T>&& status [[clang::param_typestate(unconsumed)]])
      : internal_(std::move(status)),
        log_detail_({
            .file = file,
            .line = line,
        }) {}

  StatusLinker(StatusChain<T>&& status [[clang::param_typestate(unconsumed)]],
               StatusLinkerLogDetail&& detail)
      : internal_(std::move(status)), log_detail_(std::move(detail)) {}

  StatusLinker(StatusLinker&& linker)
      : internal_(std::move(linker.internal_)),
        log_detail_(std::move(linker.log_detail_)) {}

  StatusLinker() = delete;

  ~StatusLinker() = default;

  template <int&... ExplicitArgumentBarrier,
            typename U,
            typename = std::enable_if_t<
                std::is_convertible_v<StatusChain<T>, StatusChain<U>>>>
  operator StatusChain<U>() {
    LogIfNeeded();
    return std::move(internal_);
  }

  template <int&... ExplicitArgumentBarrier,
            typename V,
            typename U,
            typename = std::enable_if_t<
                std::is_convertible_v<StatusChain<T>, StatusChainOr<V, U>>>>
  operator StatusChainOr<V, U>() {
    LogIfNeeded();
    return std::move(internal_);
  }

  // Add log message.
  template <int&... ExplicitArgumentBarrier, typename V>
  StatusLinker&& operator<<(const V& value) {
    log_detail_.stream << value;
    return std::move(*this);
  }

  // Processes with a custom handler.
  template <int&... ExplicitArgumentBarrier, typename Handler>
  auto With(Handler handler) {
    return handler(std::move(*this));
  }

  // Rewraps the internal status chain with the other status chain.
  template <typename U, int&... ExplicitArgumentBarrier, typename... Args>
  StatusLinker<U> WithStatus(Args&&... args) {
    static_assert(std::is_base_of_v<Error, U> || std::is_same_v<Error, U>,
                  "Supplied type is not derived from |Error|.");
    using MakeStatusTrait = typename U::MakeStatusTrait;
    return StatusLinker<U>(MakeStatusTrait()(std::forward<Args>(args)...)
                               .Wrap(std::move(internal_)),
                           std::move(log_detail_));
  }

  // Returns the value directly.
  template <int&... ExplicitArgumentBarrier, typename U>
  auto As(U&& value) {
    LogIfNeeded();
    return std::forward<U>(value);
  }

  // Returns void.
  void ReturnVoid() { LogIfNeeded(); }

  StatusLinker&& Log(logging::LogSeverity severity) {
    log_detail_.severity = severity;
    return std::move(*this);
  }

  StatusLinker&& LogInfo() { return Log(logging::LOGGING_INFO); }

  StatusLinker&& LogWarning() { return Log(logging::LOGGING_WARNING); }

  StatusLinker&& LogError() { return Log(logging::LOGGING_ERROR); }

 private:
  void LogIfNeeded() {
    if (log_detail_.severity.has_value() &&
        logging::ShouldCreateLogMessage(log_detail_.severity.value())) {
      logging::LogMessage logger(log_detail_.file, log_detail_.line,
                                 log_detail_.severity.value());
      std::string str = log_detail_.stream.str();
      if (!str.empty()) {
        logger.stream() << str << ": ";
      }
      logger.stream() << internal_;
    }
  }

  StatusChain<T> internal_;
  StatusLinkerLogDetail log_detail_;
};

template <class T>
StatusLinker(StatusChain<T>&&) -> StatusLinker<T>;

}  // namespace status
}  // namespace hwsec_foundation

#define RETURN_IF_ERROR(expr)                                         \
  if (auto _status_ = (expr); !_status_.ok())                         \
  return ::hwsec_foundation::status::StatusLinker(__FILE__, __LINE__, \
                                                  std::move(_status_))

// Internal helper for concatenating macro values.
#define STATUS_MACROS_CONCAT_NAME_INNER(x, y) x##y
#define STATUS_MACROS_CONCAT_NAME(x, y) STATUS_MACROS_CONCAT_NAME_INNER(x, y)

#define ASSIGN_OR_RETURN_IMPL(result, lhs, rexpr, error_expression) \
  auto result = (rexpr);                                            \
  if (!result.ok()) {                                               \
    [[maybe_unused]] ::hwsec_foundation::status::StatusLinker _(    \
        __FILE__, __LINE__, std::move(result).status());            \
    return (error_expression);                                      \
  }                                                                 \
  lhs = std::move(result).value()

#define ASSIGN_OR_RETURN_2(lhs, rexpr) \
  ASSIGN_OR_RETURN_IMPL(               \
      STATUS_MACROS_CONCAT_NAME(_status_or_value, __COUNTER__), lhs, rexpr, _)

#define ASSIGN_OR_RETURN_3(lhs, rexpr, error_expression)                    \
  ASSIGN_OR_RETURN_IMPL(                                                    \
      STATUS_MACROS_CONCAT_NAME(_status_or_value, __COUNTER__), lhs, rexpr, \
      error_expression)

#define ASSIGN_OR_RETURN_HELPER(_1, _2, _3, MACRO_NAME, ...) MACRO_NAME

#define ASSIGN_OR_RETURN(...)                                                  \
  ASSIGN_OR_RETURN_HELPER(__VA_ARGS__, ASSIGN_OR_RETURN_3, ASSIGN_OR_RETURN_2) \
  (__VA_ARGS__)

#endif  // LIBHWSEC_FOUNDATION_STATUS_STATUS_CHAIN_MACROS_H_
