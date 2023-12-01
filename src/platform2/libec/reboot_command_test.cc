// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include "libec/reboot_command.h"

namespace ec {
namespace {

TEST(RebootCommand, RebootCommand) {
  RebootCommand cmd;
  EXPECT_EQ(cmd.Version(), 0);
  EXPECT_EQ(cmd.Command(), EC_CMD_REBOOT);
}

}  // namespace
}  // namespace ec
