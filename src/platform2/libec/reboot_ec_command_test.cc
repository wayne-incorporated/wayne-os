// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include "libec/reboot_ec_command.h"

namespace ec {
namespace {

TEST(RebootEcCommand, RebootEcCommand) {
  RebootEcCommand cmd(
      ec_reboot_cmd::EC_REBOOT_HIBERNATE,
      reboot_ec::flags::kOnApShutdown | reboot_ec::flags::kReserved0);
  EXPECT_EQ(cmd.Version(), 0);
  EXPECT_EQ(cmd.Command(), EC_CMD_REBOOT_EC);
  EXPECT_EQ(cmd.Req()->cmd, ec_reboot_cmd::EC_REBOOT_HIBERNATE);
  EXPECT_EQ(cmd.Req()->flags, 3);
}

TEST(RebootEcCommand, RebootEcFlags) {
  EXPECT_EQ(reboot_ec::flags::kReserved0, 1);
  EXPECT_EQ(reboot_ec::flags::kOnApShutdown, 2);
  EXPECT_EQ(reboot_ec::flags::kSwitchRwSlot, 4);
  EXPECT_EQ(reboot_ec::flags::kClearApIdle, 8);
}

}  // namespace
}  // namespace ec
