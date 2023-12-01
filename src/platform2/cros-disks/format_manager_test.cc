// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include "cros-disks/format_manager.h"
#include "cros-disks/mock_platform.h"
#include "cros-disks/platform.h"

#include <gtest/gtest.h>

namespace cros_disks {

class FormatManagerTest : public ::testing::Test {
 protected:
  MockPlatform platform_;
  FormatManager manager_{&platform_, nullptr};
};

TEST_F(FormatManagerTest, GetFormatProgramPath) {
  EXPECT_EQ("", manager_.GetFormatProgramPath("nonexistent-fs"));
}

TEST_F(FormatManagerTest, IsFilesystemSupported) {
  EXPECT_TRUE(manager_.IsFilesystemSupported("vfat"));
  EXPECT_TRUE(manager_.IsFilesystemSupported("exfat"));
  EXPECT_TRUE(manager_.IsFilesystemSupported("ntfs"));
  EXPECT_FALSE(manager_.IsFilesystemSupported("nonexistent-fs"));
}

}  // namespace cros_disks
