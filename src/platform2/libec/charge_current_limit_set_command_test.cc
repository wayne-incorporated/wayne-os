// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libec/charge_current_limit_set_command.h"

#include <gtest/gtest.h>

namespace ec {
namespace {

TEST(ChargeCurrentLimitSetCommand, ChargeCurrentLimit) {
  uint32_t limit_mA = 650;
  ChargeCurrentLimitSetCommand cmd(limit_mA);
  EXPECT_EQ(cmd.Command(), EC_CMD_CHARGE_CURRENT_LIMIT);
  EXPECT_EQ(cmd.Req()->limit, limit_mA);
}

}  // namespace
}  // namespace ec
