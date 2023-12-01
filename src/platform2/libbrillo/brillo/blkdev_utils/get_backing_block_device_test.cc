// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/blkdev_utils/get_backing_block_device.h"

#include <memory>
#include <utility>

#include <sys/sysmacros.h>
#include <sys/types.h>

#include <base/files/file_path.h>
#include <brillo/udev/mock_udev.h>
#include <brillo/udev/mock_udev_device.h>
#include <gtest/gtest.h>

namespace brillo {

namespace {

using testing::ByMove;
using testing::Return;

constexpr char kSearchPath[] = "testdata/backing_device/sys/block";

TEST(GetBackingBlockDevice, NoUdevDev) {
  auto udev = std::make_unique<MockUdev>();
  dev_t devnum = makedev(42, 24);
  EXPECT_CALL(*udev, CreateDeviceFromDeviceNumber('b', devnum))
      .WillOnce(Return(ByMove(nullptr)));
  ASSERT_THAT(
      GetBackingPhysicalDeviceForBlock(devnum, kSearchPath, std::move(udev)),
      base::FilePath());
}

TEST(GetBackingBlockDevice, Direct) {
  auto udev = std::make_unique<MockUdev>();
  auto udev_dev = std::make_unique<MockUdevDevice>();
  constexpr char dev_node[] = "/dev/sda";
  dev_t devnum = makedev(42, 24);
  EXPECT_CALL(*udev_dev, GetDeviceNode()).WillOnce(Return(dev_node));
  EXPECT_CALL(*udev, CreateDeviceFromDeviceNumber('b', devnum))
      .WillOnce(Return(ByMove(std::move(udev_dev))));
  ASSERT_THAT(
      GetBackingPhysicalDeviceForBlock(devnum, kSearchPath, std::move(udev)),
      base::FilePath(dev_node));
}

TEST(GetBackingBlockDevice, InDirect) {
  auto udev = std::make_unique<MockUdev>();
  auto udev_dev = std::make_unique<MockUdevDevice>();
  constexpr char dev_node[] = "/dev/dm-1";
  constexpr char backing_node[] = "/dev/sda";
  dev_t devnum = makedev(42, 24);
  EXPECT_CALL(*udev_dev, GetDeviceNode()).WillOnce(Return(dev_node));
  EXPECT_CALL(*udev, CreateDeviceFromDeviceNumber('b', devnum))
      .WillOnce(Return(ByMove(std::move(udev_dev))));
  ASSERT_THAT(
      GetBackingPhysicalDeviceForBlock(devnum, kSearchPath, std::move(udev)),
      base::FilePath(backing_node));
}

}  // namespace

}  // namespace brillo
