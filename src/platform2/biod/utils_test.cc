// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "biod/utils.h"

#include <string>

#include <gtest/gtest.h>

namespace biod {

TEST(UtilsTest, LogSafeID_Normal) {
  EXPECT_EQ(LogSafeID("0123456789_ABCDEF_0123456789"), "01*");
}

TEST(UtilsTest, LogSafeID_Small) {
  EXPECT_EQ(LogSafeID("K"), "K");
}

TEST(UtilsTest, LogSafeID_BlankString) {
  EXPECT_EQ(LogSafeID(""), "");
}

}  // namespace biod
