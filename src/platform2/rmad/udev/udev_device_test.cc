// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/udev/udev_device.h"

#include <memory>
#include <utility>

#include <brillo/udev/mock_udev_device.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using testing::ByMove;
using testing::Eq;
using testing::Return;
using testing::StrictMock;

namespace rmad {

class UdevDeviceTest : public testing::Test {
 public:
  UdevDeviceTest() = default;
  ~UdevDeviceTest() override = default;
};

TEST_F(UdevDeviceTest, IsRemovable) {
  auto dev = std::make_unique<StrictMock<brillo::MockUdevDevice>>();
  EXPECT_CALL(*dev, GetSysAttributeValue(Eq("removable")))
      .WillOnce(Return("1"));

  auto udev_device = std::make_unique<UdevDeviceImpl>(std::move(dev));
  EXPECT_TRUE(udev_device->IsRemovable());
}

TEST_F(UdevDeviceTest, IsNotRemovable) {
  auto dev = std::make_unique<StrictMock<brillo::MockUdevDevice>>();
  EXPECT_CALL(*dev, GetSysAttributeValue(Eq("removable")))
      .WillOnce(Return("0"));
  EXPECT_CALL(*dev, GetParent()).WillOnce(Return(ByMove(nullptr)));

  auto udev_device = std::make_unique<UdevDeviceImpl>(std::move(dev));
  EXPECT_FALSE(udev_device->IsRemovable());
}

TEST_F(UdevDeviceTest, IsRemovable_MultiLayer) {
  auto parent_dev = std::make_unique<StrictMock<brillo::MockUdevDevice>>();
  EXPECT_CALL(*parent_dev, GetSysAttributeValue(Eq("removable")))
      .WillOnce(Return("1"));

  auto dev = std::make_unique<StrictMock<brillo::MockUdevDevice>>();
  EXPECT_CALL(*dev, GetSysAttributeValue(Eq("removable")))
      .WillOnce(Return("0"));
  EXPECT_CALL(*dev, GetParent())
      .WillOnce(Return(ByMove(std::move(parent_dev))));

  auto udev_device = std::make_unique<UdevDeviceImpl>(std::move(dev));
  EXPECT_TRUE(udev_device->IsRemovable());
}

TEST_F(UdevDeviceTest, GetSysPath) {
  auto dev = std::make_unique<StrictMock<brillo::MockUdevDevice>>();
  EXPECT_CALL(*dev, GetSysPath()).WillOnce(Return("/sys/path"));

  auto udev_device = std::make_unique<UdevDeviceImpl>(std::move(dev));
  EXPECT_EQ("/sys/path", udev_device->GetSysPath());
}

TEST_F(UdevDeviceTest, GetDeviceNode) {
  auto dev = std::make_unique<StrictMock<brillo::MockUdevDevice>>();
  EXPECT_CALL(*dev, GetDeviceNode()).WillOnce(Return("/dev/path"));

  auto udev_device = std::make_unique<UdevDeviceImpl>(std::move(dev));
  EXPECT_EQ("/dev/path", udev_device->GetDeviceNode());
}

}  // namespace rmad
