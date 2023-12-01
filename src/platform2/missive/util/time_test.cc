// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/util/time.h"

#include <gtest/gtest.h>

#include "missive/util/status_macros.h"

using ::testing::Ge;

namespace reporting {
namespace {

TEST(TimeTest, SucceedInGettingCurrentTime) {
  // Test the methods succeed under normal conditions. There is not much we can
  // test here.
  ASSERT_OK(GetCurrentTime(TimeType::kWall))
      << "Failed to get wall-clock time.";
  ASSERT_OK(GetCurrentTime(TimeType::kProcessCpu))
      << "Failed to get CPU time used by the process.";
}

}  // namespace
}  // namespace reporting
