// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "biod/mock_cros_fp_device.h"
#include "libec/fingerprint/fp_context_command_factory.h"

using testing::Return;

namespace ec {
namespace {

TEST(FpContextCommandFactory, Create_v1) {
  biod::MockCrosFpDevice mock_cros_fp_device;
  EXPECT_CALL(mock_cros_fp_device, EcCmdVersionSupported)
      .Times(1)
      .WillOnce(Return(EcCmdVersionSupportStatus::SUPPORTED));

  auto cmd = FpContextCommandFactory::Create(&mock_cros_fp_device, "DEADBEEF");
  EXPECT_TRUE(cmd);
  EXPECT_EQ(cmd->Version(), 1);
}

TEST(FpContextCommandFactory, Create_v0) {
  biod::MockCrosFpDevice mock_cros_fp_device;
  EXPECT_CALL(mock_cros_fp_device, EcCmdVersionSupported)
      .Times(1)
      .WillOnce(Return(EcCmdVersionSupportStatus::UNSUPPORTED));

  auto cmd = FpContextCommandFactory::Create(&mock_cros_fp_device, "DEADBEEF");
  EXPECT_TRUE(cmd);
  EXPECT_EQ(cmd->Version(), 0);
}

TEST(FpContextCommandFactory, Create_Version_Supported_Unknown) {
  biod::MockCrosFpDevice mock_cros_fp_device;
  EXPECT_CALL(mock_cros_fp_device, EcCmdVersionSupported)
      .Times(1)
      .WillOnce(Return(EcCmdVersionSupportStatus::UNKNOWN));

  auto cmd = FpContextCommandFactory::Create(&mock_cros_fp_device, "DEADBEEF");
  EXPECT_TRUE(cmd);
  EXPECT_EQ(cmd->Version(), 0);
}

}  // namespace
}  // namespace ec
