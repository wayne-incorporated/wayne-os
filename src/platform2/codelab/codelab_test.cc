// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "codelab/codelab.h"

#include <gtest/gtest.h>

namespace codelab {

TEST(CodelabTest, GivesFive) {
  EXPECT_EQ(GiveFive(), 5);
}

// TODO(reader): Make this test pass!
TEST(CodelabTest, DISABLED_Multiply) {
  EXPECT_EQ(Multiply(6, 7), 42);
}

}  // namespace codelab
