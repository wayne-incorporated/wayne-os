// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include "libec/set_mkbp_wake_mask_command.h"

namespace ec {
namespace {

TEST(SetMkbpWakeMaskCommand, SetMkbpWakeMaskCommand) {
  SetMkbpWakeMaskCommand cmd(EC_MKBP_HOST_EVENT_WAKE_MASK,
                             EC_HOST_EVENT_MASK(EC_HOST_EVENT_LID_CLOSED));
  EXPECT_EQ(cmd.Version(), 0);
  EXPECT_EQ(cmd.Command(), EC_CMD_MKBP_WAKE_MASK);
  EXPECT_EQ(cmd.Req()->action, SET_WAKE_MASK);
  EXPECT_EQ(cmd.Req()->mask_type, EC_MKBP_HOST_EVENT_WAKE_MASK);
  EXPECT_EQ(cmd.Req()->new_wake_mask, 1);
}

TEST(SetMkbpWakeMaskHostEventCommand, SetMkbpWakeMaskHostEventCommand) {
  SetMkbpWakeMaskHostEventCommand cmd(
      EC_HOST_EVENT_MASK(EC_HOST_EVENT_LID_CLOSED));
  EXPECT_EQ(cmd.Version(), 0);
  EXPECT_EQ(cmd.Command(), EC_CMD_MKBP_WAKE_MASK);
  EXPECT_EQ(cmd.Req()->action, SET_WAKE_MASK);
  EXPECT_EQ(cmd.Req()->mask_type, EC_MKBP_HOST_EVENT_WAKE_MASK);
  EXPECT_EQ(cmd.Req()->new_wake_mask, 1);
}

TEST(SetMkbpWakeMaskEventCommand, SetMkbpWakeMaskEventCommand) {
  SetMkbpWakeMaskEventCommand cmd(EC_HOST_EVENT_MASK(EC_MKBP_EVENT_BUTTON));
  EXPECT_EQ(cmd.Version(), 0);
  EXPECT_EQ(cmd.Command(), EC_CMD_MKBP_WAKE_MASK);
  EXPECT_EQ(cmd.Req()->action, SET_WAKE_MASK);
  EXPECT_EQ(cmd.Req()->mask_type, EC_MKBP_EVENT_WAKE_MASK);
  EXPECT_EQ(cmd.Req()->new_wake_mask, 4);
}

}  // namespace
}  // namespace ec
