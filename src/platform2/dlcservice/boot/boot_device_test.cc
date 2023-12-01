// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "dlcservice/boot/boot_device.h"

#include <gtest/gtest.h>

namespace dlcservice {

class BootDeviceTest : public testing::Test {};

TEST_F(BootDeviceTest, SysfsBlockDeviceTest) {
  BootDevice boot_device;
  EXPECT_EQ("/sys/block/sda", boot_device.SysfsBlockDevice("/dev/sda"));
  EXPECT_EQ("", boot_device.SysfsBlockDevice("/foo/sda"));
  EXPECT_EQ("", boot_device.SysfsBlockDevice("/dev/foo/bar"));
  EXPECT_EQ("", boot_device.SysfsBlockDevice("/"));
  EXPECT_EQ("", boot_device.SysfsBlockDevice("./"));
  EXPECT_EQ("", boot_device.SysfsBlockDevice(""));
}

}  // namespace dlcservice
