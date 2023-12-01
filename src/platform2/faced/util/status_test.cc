// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "faced/util/status.h"

#include <string>

#include <absl/status/status.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "faced/testing/status.h"

namespace faced {
namespace {

// Run FACE_RETURN_IF_ERROR on an `OkStatus`.
TEST(Status, ReturnIfErrorOkValue) {
  auto result = []() -> absl::StatusOr<int> {
    FACE_RETURN_IF_ERROR(absl::OkStatus());
    return 42;
  }();
  FACE_ASSERT_OK(result);
  EXPECT_EQ(result.value(), 42);
}

// Run FACE_RETURN_IF_ERROR on an error value.
TEST(Status, ReturnIfErrorErrorValue) {
  auto result = []() -> absl::StatusOr<int> {
    FACE_RETURN_IF_ERROR(absl::InternalError("error"));
    CHECK(false) << "Should not be reached.";
    return 42;
  }();
  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.status(), absl::InternalError("error"));
}

// Run FACE_ASSIGN_OR_RETURN on a non-error value.
TEST(Status, AssignOrReturnOkValue) {
  auto result = []() -> absl::StatusOr<std::string> {
    FACE_ASSIGN_OR_RETURN(int x, absl::StatusOr<int>(42));
    EXPECT_EQ(x, 42);
    return "success";
  }();
  FACE_ASSERT_OK(result);
  EXPECT_EQ(result.value(), "success");
}

// Run FACE_ASSIGN_OR_RETURN on an error value.
TEST(Status, AssignOrReturnErrorValue) {
  auto result = []() -> absl::StatusOr<int> {
    FACE_ASSIGN_OR_RETURN(int x,
                          absl::StatusOr<int>(absl::InternalError("error")));
    (void)x;
    CHECK(false) << "Should not be reached.";
    return 0;
  }();
  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.status(), absl::InternalError("error"));
}

}  // namespace
}  // namespace faced
