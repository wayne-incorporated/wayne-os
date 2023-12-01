// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "biod/biod_system.h"

namespace biod {
namespace {

using ::testing::Return;

class BiodSystemTest : public testing::Test {
 public:
  class MockBiodSystem : public BiodSystem {
   public:
    MOCK_METHOD(int,
                VbGetSystemPropertyInt,
                (const std::string&),
                (override, const));
  };
};

TEST_F(BiodSystemTest, IsHardwareWriteProtectEnabledTrue) {
  MockBiodSystem biod_system;
  EXPECT_CALL(biod_system, VbGetSystemPropertyInt("wpsw_cur"))
      .WillOnce(Return(1));
  EXPECT_TRUE(biod_system.HardwareWriteProtectIsEnabled());
}

TEST_F(BiodSystemTest, IsHardwareWriteProtectEnabledFalse) {
  MockBiodSystem biod_system;
  EXPECT_CALL(biod_system, VbGetSystemPropertyInt("wpsw_cur"))
      .WillOnce(Return(0));
  EXPECT_FALSE(biod_system.HardwareWriteProtectIsEnabled());
}

TEST_F(BiodSystemTest, IsDevModeBootFromSignedKernelTrue) {
  MockBiodSystem biod_system;
  EXPECT_CALL(biod_system, VbGetSystemPropertyInt("dev_boot_signed_only"))
      .WillOnce(Return(1));
  EXPECT_TRUE(biod_system.OnlyBootSignedKernel());
}

TEST_F(BiodSystemTest, IsDevModeBootFromSignedKernelFalse) {
  MockBiodSystem biod_system;
  EXPECT_CALL(biod_system, VbGetSystemPropertyInt("dev_boot_signed_only"))
      .WillOnce(Return(0));
  EXPECT_FALSE(biod_system.OnlyBootSignedKernel());
}

}  // namespace
}  // namespace biod
