// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include "libec/rwsig_action_command.h"

namespace ec {
namespace {

TEST(RWSigActionCommand, RWSigActionCommand) {
  RWSigActionCommand cmd_abort(RWSIG_ACTION_ABORT);
  EXPECT_EQ(cmd_abort.Version(), 0);
  EXPECT_EQ(cmd_abort.Command(), EC_CMD_RWSIG_ACTION);
  EXPECT_EQ(cmd_abort.Req()->action, RWSIG_ACTION_ABORT);

  RWSigActionCommand cmd_continue(RWSIG_ACTION_CONTINUE);
  EXPECT_EQ(cmd_continue.Version(), 0);
  EXPECT_EQ(cmd_continue.Command(), EC_CMD_RWSIG_ACTION);
  EXPECT_EQ(cmd_continue.Req()->action, RWSIG_ACTION_CONTINUE);
}

}  // namespace
}  // namespace ec
