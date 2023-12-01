// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>
#include "libec/rand_num_params.h"

namespace ec {
namespace {

TEST(RandNumParam, Size) {
  EXPECT_EQ(sizeof(rand::RandNumResp), kMaxPacketSize);
  EXPECT_EQ(sizeof(ec_response_rand_num), 0);
}

}  // namespace
}  // namespace ec
