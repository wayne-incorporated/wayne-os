// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include "ml/simple.h"

namespace ml {
namespace simple {
namespace {

void TestAdd(const double x, const double y, const double expected) {
  // TODO(avg): tests for NNAPI, when available
  auto result = Add(x, y, false, false, "OPENGL");
  ASSERT_NEAR(result.sum, expected, 0.0001);
  ASSERT_EQ(result.status, "OK");
}

TEST(AddTest, Working) {
  TestAdd(1.0, 2.0, 3.0);
  TestAdd(-1.0, 2.0, 1.0);
  TestAdd(0.1, 25.2, 25.3);
}

}  // namespace
}  // namespace simple
}  // namespace ml
