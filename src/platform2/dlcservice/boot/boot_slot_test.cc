// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "dlcservice/boot/boot_slot.h"

#include <utility>

#include <base/files/file_path.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "dlcservice/boot/mock_boot_device.h"

namespace dlcservice {

class BootSlotTest : public testing::Test {
 public:
  BootSlotTest() {
    auto mock_boot_device = std::make_unique<MockBootDevice>();
    boot_device_ = mock_boot_device.get();
    boot_slot_ = std::make_unique<BootSlot>(std::move(mock_boot_device));
  }

 protected:
  MockBootDevice* boot_device_;
  std::unique_ptr<BootSlot> boot_slot_;
};

TEST_F(BootSlotTest, NonRemovableDeviceSlotA) {
  const std::string& kDeviceName("/dev/sda");
  EXPECT_CALL(*boot_device_, GetBootDevice())
      .WillOnce(testing::Return(base::FilePath{kDeviceName + "3"}));
  EXPECT_CALL(*boot_device_, IsRemovableDevice(testing::_))
      .WillOnce(testing::Return(false));
  ASSERT_TRUE(boot_slot_->Init());
  EXPECT_EQ(boot_slot_->GetSlot(), BootSlot::Slot::A);
  EXPECT_EQ(boot_slot_->GetDeviceName(), kDeviceName);
  EXPECT_FALSE(boot_slot_->IsDeviceRemovable());
}

TEST_F(BootSlotTest, NonRemovableDeviceSlotB) {
  const std::string& kDeviceName("/dev/sda");
  EXPECT_CALL(*boot_device_, GetBootDevice())
      .WillOnce(testing::Return(base::FilePath{kDeviceName + "5"}));
  EXPECT_CALL(*boot_device_, IsRemovableDevice(testing::_))
      .WillOnce(testing::Return(false));
  ASSERT_TRUE(boot_slot_->Init());
  EXPECT_EQ(boot_slot_->GetSlot(), BootSlot::Slot::B);
  EXPECT_EQ(boot_slot_->GetDeviceName(), kDeviceName);
  EXPECT_FALSE(boot_slot_->IsDeviceRemovable());
}

TEST_F(BootSlotTest, RemovableDeviceSlotA) {
  const std::string& kDeviceName("/dev/sda");
  EXPECT_CALL(*boot_device_, GetBootDevice())
      .WillOnce(testing::Return(base::FilePath{kDeviceName + "3"}));
  EXPECT_CALL(*boot_device_, IsRemovableDevice(testing::_))
      .WillOnce(testing::Return(true));
  ASSERT_TRUE(boot_slot_->Init());
  EXPECT_EQ(boot_slot_->GetSlot(), BootSlot::Slot::A);
  EXPECT_EQ(boot_slot_->GetDeviceName(), kDeviceName);
  EXPECT_TRUE(boot_slot_->IsDeviceRemovable());
}

TEST_F(BootSlotTest, RemovableDeviceSlotB) {
  const std::string& kDeviceName("/dev/sda");
  EXPECT_CALL(*boot_device_, GetBootDevice())
      .WillOnce(testing::Return(base::FilePath{kDeviceName + "5"}));
  EXPECT_CALL(*boot_device_, IsRemovableDevice(testing::_))
      .WillOnce(testing::Return(true));
  ASSERT_TRUE(boot_slot_->Init());
  EXPECT_EQ(boot_slot_->GetSlot(), BootSlot::Slot::B);
  EXPECT_EQ(boot_slot_->GetDeviceName(), kDeviceName);
  EXPECT_TRUE(boot_slot_->IsDeviceRemovable());
}

TEST_F(BootSlotTest, InvalidPartitionNumber) {
  const std::string& kDeviceName("/dev/sda");
  EXPECT_CALL(*boot_device_, GetBootDevice())
      .WillOnce(testing::Return(base::FilePath{kDeviceName + "777"}));
  EXPECT_CALL(*boot_device_, IsRemovableDevice(testing::_))
      .WillOnce(testing::Return(true));
  ASSERT_FALSE(boot_slot_->Init());
}

TEST_F(BootSlotTest, MissingPartitionNumber) {
  const std::string& kDeviceName("/dev/sda");
  EXPECT_CALL(*boot_device_, GetBootDevice())
      .WillOnce(testing::Return(base::FilePath{kDeviceName}));
  EXPECT_CALL(*boot_device_, IsRemovableDevice(testing::_)).Times(0);
  EXPECT_FALSE(boot_slot_->Init());
}

}  // namespace dlcservice
