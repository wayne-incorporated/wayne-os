// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FACED_UTIL_STATUS_H_
#define FACED_UTIL_STATUS_H_

#include <algorithm>
#include <utility>

#include <absl/status/status.h>
#include <absl/status/statusor.h>
#include <base/check.h>

namespace faced {

// Return the value of the given absl::StatusOr<T> type, or abort the
// program with a CHECK failure if the input is an error value.
template <typename T>
typename T::value_type ValueOrDie(T&& status_or_value) {
  CHECK(status_or_value.ok()) << status_or_value.status();
  return *std::move(status_or_value);
}

// Given an expression that returns an absl::Status, return with
// the error from the current function if it is an error status,
// or continue execution if not.
//
// Used as follows:
//
//   absl::Status MyFunction() {
//     // If `SomeFunction` returns an error, return directly from the
//     // function.
//     FACE_RETURN_IF_ERROR(SomeFunction());
//
//     // Ditto, but for `OtherFunction`.
//     FACE_RETURN_IF_ERROR(OtherFunction());
//
//     //  ...
//   }
//
#define FACE_RETURN_IF_ERROR(rexpr) \
  do {                              \
    auto status = (rexpr);          \
    if (!status.ok()) {             \
      return status;                \
    }                               \
  } while (false)

// Call a function that returns an absl::StatusOr<T> type. Assign the value
// to a variable on success, or return from the current function on failure.
//
// Used as follows:
//
//   absl::StatusOr<std::string> MaybeReturnString();
//
//   absl::Status MyFunction() {
//     // Call the function `MaybeReturnString`. On error, return the
//     // status directly. On success, assign the result to a variable
//     // `result`.
//     FACE_ASSIGN_OR_RETURN(std::string result, MaybeReturnString());
//
//     std::cout << result;  // `result` is a plain string, not an
//                           // absl::StatusOr<std::string>
//     //  ...
//   }
//
#define FACE_ASSIGN_OR_RETURN(var, expr)                                     \
  auto FACE_STATUS_IMPL_CONCAT_(statusor, __LINE__) = (expr);                \
  if (!FACE_STATUS_IMPL_CONCAT_(statusor, __LINE__).ok()) {                  \
    return std::move(FACE_STATUS_IMPL_CONCAT_(statusor, __LINE__)).status(); \
  }                                                                          \
  var = *std::move(FACE_STATUS_IMPL_CONCAT_(statusor, __LINE__))

//
// Implementation details follow.
//

// Internal helper macros for concatenating macro values.
#define FACE_STATUS_IMPL_CONCAT_INNER_(x, y) x##y
#define FACE_STATUS_IMPL_CONCAT_(x, y) FACE_STATUS_IMPL_CONCAT_INNER_(x, y)

}  // namespace faced

#endif  // FACED_UTIL_STATUS_H_
