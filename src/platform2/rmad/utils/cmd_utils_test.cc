// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/utils/cmd_utils_impl.h"

#include <string>

#include <gtest/gtest.h>

namespace rmad {

class CmdUtilsImplTest : public testing::Test {
 public:
  CmdUtilsImplTest() = default;
  ~CmdUtilsImplTest() override = default;
};

TEST_F(CmdUtilsImplTest, GetOutput_Success) {
  CmdUtilsImpl cmd_utils;
  std::string output;
  EXPECT_TRUE(cmd_utils.GetOutput({"echo", "test"}, &output));
  EXPECT_EQ(output, "test\n");
}

TEST_F(CmdUtilsImplTest, GetOutput_Fail) {
  CmdUtilsImpl cmd_utils;
  EXPECT_DEATH(cmd_utils.GetOutput({"echo", "test"}, nullptr), "");
}

TEST_F(CmdUtilsImplTest, GetOutputAndError_Success) {
  CmdUtilsImpl cmd_utils;
  std::string output;
  EXPECT_TRUE(cmd_utils.GetOutputAndError({"echo", "test"}, &output));
  EXPECT_EQ(output, "test\n");
}

TEST_F(CmdUtilsImplTest, GetOutputAndError_Fail) {
  CmdUtilsImpl cmd_utils;
  EXPECT_DEATH(cmd_utils.GetOutputAndError({"echo", "test"}, nullptr), "");
}

}  // namespace rmad
