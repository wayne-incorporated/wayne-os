// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libec/add_entropy_command.h"

namespace ec {
namespace {

using ::testing::Return;

TEST(AddEntropyCommand, AddEntropyCommand) {
  AddEntropyCommand cmd(false);
  EXPECT_EQ(cmd.Version(), 0);
  EXPECT_EQ(cmd.Command(), EC_CMD_ADD_ENTROPY);
  EXPECT_EQ(cmd.Req()->action, ADD_ENTROPY_ASYNC);
  EXPECT_EQ(cmd.options().poll_for_result_num_attempts, 20);
  EXPECT_EQ(cmd.options().poll_interval, base::Milliseconds(100));
  EXPECT_EQ(cmd.options().validate_poll_result, false);
}

TEST(AddEntropyCommand, AddEntropyCommandReset) {
  AddEntropyCommand cmd(true);
  EXPECT_EQ(cmd.Version(), 0);
  EXPECT_EQ(cmd.Command(), EC_CMD_ADD_ENTROPY);
  EXPECT_EQ(cmd.Req()->action, ADD_ENTROPY_RESET_ASYNC);
  EXPECT_EQ(cmd.options().poll_for_result_num_attempts, 20);
  EXPECT_EQ(cmd.options().poll_interval, base::Milliseconds(100));
  EXPECT_EQ(cmd.options().validate_poll_result, false);
}

}  // namespace
}  // namespace ec
