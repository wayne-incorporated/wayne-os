// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FACED_TESTING_STATUS_H_
#define FACED_TESTING_STATUS_H_

#include <algorithm>
#include <string>
#include <utility>

#include <absl/status/status.h>
#include <absl/status/statusor.h>
#include <base/check.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace faced {

// Forward declarations.
namespace testing_internal {
inline std::string ErrorStatusToString(const absl::Status&);
template <typename T>
inline std::string ErrorStatusToString(const absl::StatusOr<T>&);
}  // namespace testing_internal

// Assert/expect the given `absl::Status` or `absl::StatusOr<T>` object is
// OkStatus.
#define FACE_ASSERT_OK(expr) ASSERT_THAT(expr, ::faced::IsOk())
#define FACE_EXPECT_OK(expr) EXPECT_THAT(expr, ::faced::IsOk())

// Assign the given absl::StatusOr<T> object to a variable, or fail the current
// test if the status is an error object.
//
// Used as follows:
//
//   absl::StatusOr<std::string> MaybeReturnString();
//
//   TEST(MyTest, SomeTest) {
//     FACE_ASSERT_OK_AND_ASSIGN(std::string, MaybeReturnString());
//
//     std::cout << result;  // `result` is a plain string, not an
//                           // absl::StatusOr<std::string>
//   }
//
#define FACE_ASSERT_OK_AND_ASSIGN(var, expr)                                  \
  auto FACE_STATUS_TEST_IMPL_CONCAT_(statusor, __LINE__) = (expr);            \
  FACE_ASSERT_OK(FACE_STATUS_TEST_IMPL_CONCAT_(statusor, __LINE__).status()); \
  var = *std::move(FACE_STATUS_TEST_IMPL_CONCAT_(statusor, __LINE__))

// gMock matcher to check that a absl::Status or absl::StatusOr<T> object is
// not an error.
//
// Can be used as follows:
//
//   EXPECT_THAT(my_value, IsOk());
//   ASSERT_THAT(other_value, IsOk());
//
MATCHER(IsOk, "") {
  if (!arg.ok()) {
    *result_listener << ::faced::testing_internal::ErrorStatusToString(arg);
    return false;
  }
  *result_listener << "ok status";
  return true;
}

//
// Implementation details follow.
//

// Internal helper macros for concatenating macro values.
#define FACE_STATUS_TEST_IMPL_CONCAT_INNER_(x, y) x##y
#define FACE_STATUS_TEST_IMPL_CONCAT_(x, y) \
  FACE_STATUS_TEST_IMPL_CONCAT_INNER_(x, y)

namespace testing_internal {

// Internal function to convert a non-OK `absl::Status` or `absl::StatusOr<T>`
// error to a string.
inline std::string ErrorStatusToString(const absl::Status& s) {
  return s.ToString();
}
template <typename T>
inline std::string ErrorStatusToString(const absl::StatusOr<T>& s) {
  return s.status().ToString();
}

}  // namespace testing_internal

}  // namespace faced

#endif  // FACED_TESTING_STATUS_H_
