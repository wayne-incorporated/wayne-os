// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>
#include "libec/i2c_passthru_params.h"

namespace ec {
namespace {

TEST(I2cPassthruParams, HeaderSize) {
  EXPECT_EQ(sizeof(i2c_passthru::Params::Header),
            sizeof(ec_params_i2c_passthru));
}

TEST(I2cPassthruParams, ParamsSize) {
  EXPECT_EQ(sizeof(i2c_passthru::Params), kMaxPacketSize);
}

TEST(I2cPassthruResponse, HeaderSize) {
  EXPECT_EQ(sizeof(i2c_passthru::Response::Header),
            sizeof(ec_response_i2c_passthru));
}

TEST(I2cPassthruResponse, ParamsSize) {
  EXPECT_EQ(sizeof(i2c_passthru::Response), kMaxPacketSize);
}

}  // namespace
}  // namespace ec
