// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <brillo/blkdev_utils/loop_device_fake.h>

#include <base/files/file_util.h>
#include <gtest/gtest.h>

namespace brillo {

TEST(LoopDeviceTest, GeneralTest) {
  base::FilePath loop_backing_file;
  base::CreateTemporaryFile(&loop_backing_file);
  fake::FakeLoopDeviceManager loop_manager;

  // Create a new device
  std::unique_ptr<LoopDevice> device =
      loop_manager.AttachDeviceToFile(loop_backing_file);
  std::unique_ptr<LoopDevice> device1 =
      loop_manager.AttachDeviceToFile(loop_backing_file);
  std::unique_ptr<LoopDevice> device2 =
      loop_manager.AttachDeviceToFile(loop_backing_file);

  EXPECT_TRUE(device->IsValid());
  EXPECT_TRUE(device1->IsValid());
  EXPECT_TRUE(device2->IsValid());

  std::vector<std::unique_ptr<LoopDevice>> attached_devices =
      loop_manager.GetAttachedDevices();

  // Expect 3 devices
  EXPECT_EQ(attached_devices.size(), 3);

  device2->SetName("Loopy");

  std::unique_ptr<LoopDevice> device1_copy =
      loop_manager.GetAttachedDeviceByNumber(1);
  EXPECT_TRUE(device1_copy->IsValid());
  EXPECT_EQ(device1->GetDevicePath(), device1_copy->GetDevicePath());
  EXPECT_EQ(device1->GetBackingFilePath(), device1_copy->GetBackingFilePath());

  std::unique_ptr<LoopDevice> device2_copy =
      loop_manager.GetAttachedDeviceByName("Loopy");
  EXPECT_TRUE(device2_copy->IsValid());
  EXPECT_EQ(device2->GetDevicePath(), device2_copy->GetDevicePath());
  EXPECT_EQ(device2->GetBackingFilePath(), device2_copy->GetBackingFilePath());

  // Check double detach
  EXPECT_TRUE(device->Detach());
  EXPECT_TRUE(device1->Detach());
  EXPECT_FALSE(device1_copy->Detach());
  EXPECT_TRUE(device2->Detach());
  EXPECT_FALSE(device2_copy->Detach());
}

}  // namespace brillo
