// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libec/charge_control_set_command.h"

namespace ec {
namespace {

using ::testing::Return;

TEST(ChargeControlSetCommand, ChargeControlSetCommandNormal) {
  // Default constructor sets CHARGE_CONTROL_NORMAL
  ChargeControlSetCommand cmd;
  EXPECT_EQ(cmd.Command(), EC_CMD_CHARGE_CONTROL);
  EXPECT_GE(cmd.Version(), 2);
  EXPECT_EQ(cmd.Req()->cmd, EC_CHARGE_CONTROL_CMD_SET);
  EXPECT_EQ(cmd.Req()->mode, CHARGE_CONTROL_NORMAL);
}

TEST(ChargeControlSetCommand, ChargeControlSetCommandSustain) {
  ChargeControlSetCommand cmd(CHARGE_CONTROL_NORMAL, 70, 80);
  EXPECT_EQ(cmd.Command(), EC_CMD_CHARGE_CONTROL);
  EXPECT_GE(cmd.Version(), 2);
  EXPECT_EQ(cmd.Req()->cmd, EC_CHARGE_CONTROL_CMD_SET);
  EXPECT_EQ(cmd.Req()->mode, CHARGE_CONTROL_NORMAL);
  EXPECT_EQ(cmd.Req()->sustain_soc.lower, 70);
  EXPECT_EQ(cmd.Req()->sustain_soc.upper, 80);
}

TEST(ChargeControlSetCommand, ChargeControlSetCommandIdle) {
  ChargeControlSetCommand cmd(CHARGE_CONTROL_IDLE);
  EXPECT_EQ(cmd.Command(), EC_CMD_CHARGE_CONTROL);
  EXPECT_GE(cmd.Version(), 2);
  EXPECT_EQ(cmd.Req()->cmd, EC_CHARGE_CONTROL_CMD_SET);
  EXPECT_EQ(cmd.Req()->mode, CHARGE_CONTROL_IDLE);
}

TEST(ChargeControlSetCommand, ChargeControlSetCommandDischarge) {
  ChargeControlSetCommand cmd(CHARGE_CONTROL_DISCHARGE);
  EXPECT_EQ(cmd.Command(), EC_CMD_CHARGE_CONTROL);
  EXPECT_GE(cmd.Version(), 2);
  EXPECT_EQ(cmd.Req()->cmd, EC_CHARGE_CONTROL_CMD_SET);
  EXPECT_EQ(cmd.Req()->mode, CHARGE_CONTROL_DISCHARGE);
}

}  // namespace
}  // namespace ec
