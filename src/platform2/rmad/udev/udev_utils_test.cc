// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/udev/udev_utils.h"

#include <memory>
#include <utility>

#include <brillo/udev/mock_udev.h>
#include <brillo/udev/mock_udev_device.h>
#include <brillo/udev/mock_udev_enumerate.h>
#include <brillo/udev/mock_udev_list_entry.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "rmad/udev/udev_device.h"

using testing::_;
using testing::ByMove;
using testing::Eq;
using testing::Invoke;
using testing::NiceMock;
using testing::Return;
using testing::StrictMock;

namespace rmad {

class UdevUtilsTest : public testing::Test {
 public:
  UdevUtilsTest() = default;
  ~UdevUtilsTest() override = default;
};

TEST_F(UdevUtilsTest, EnumerateBlockDevices) {
  // Mock UdevListEntry.
  auto entry2 = std::make_unique<StrictMock<brillo::MockUdevListEntry>>();
  EXPECT_CALL(*entry2, GetNext()).WillOnce(Return(ByMove(nullptr)));
  EXPECT_CALL(*entry2, GetName()).WillOnce(Return("/sys/test/path2"));
  auto entry1 = std::make_unique<StrictMock<brillo::MockUdevListEntry>>();
  EXPECT_CALL(*entry1, GetNext()).WillOnce(Return(ByMove(std::move(entry2))));
  EXPECT_CALL(*entry1, GetName()).WillOnce(Return("/sys/test/path1"));

  // Mock UdevEnumerate.
  auto enumerate = std::make_unique<StrictMock<brillo::MockUdevEnumerate>>();
  EXPECT_CALL(*enumerate, AddMatchSubsystem(_)).WillOnce(Return(true));
  EXPECT_CALL(*enumerate, ScanDevices()).WillOnce(Return(true));
  EXPECT_CALL(*enumerate, GetListEntry())
      .WillOnce(Return(ByMove(std::move(entry1))));

  // Mock Udev.
  auto udev = std::make_unique<StrictMock<brillo::MockUdev>>();
  EXPECT_CALL(*udev, CreateEnumerate())
      .WillOnce(Return(ByMove(std::move(enumerate))));
  EXPECT_CALL(*udev, CreateDeviceFromSysPath(_))
      .Times(2)
      .WillRepeatedly(Invoke([](const char* sys_path) {
        // Mock UdevDevice.
        auto device = std::make_unique<NiceMock<brillo::MockUdevDevice>>();
        ON_CALL(*device, GetSysPath()).WillByDefault(Return(sys_path));
        return device;
      }));

  auto udev_utils = std::make_unique<UdevUtilsImpl>(std::move(udev));
  std::vector<std::unique_ptr<UdevDevice>> devices =
      udev_utils->EnumerateBlockDevices();
  EXPECT_EQ(2, devices.size());
  EXPECT_EQ("/sys/test/path1", devices[0]->GetSysPath());
  EXPECT_EQ("/sys/test/path2", devices[1]->GetSysPath());
}

TEST_F(UdevUtilsTest, GetBlockDeviceFromDevicePath) {
  // Mock UdevListEntry.
  auto entry2 = std::make_unique<StrictMock<brillo::MockUdevListEntry>>();
  EXPECT_CALL(*entry2, GetNext()).WillOnce(Return(ByMove(nullptr)));
  EXPECT_CALL(*entry2, GetName()).WillOnce(Return("/sys/test/path2"));
  auto entry1 = std::make_unique<StrictMock<brillo::MockUdevListEntry>>();
  EXPECT_CALL(*entry1, GetNext()).WillOnce(Return(ByMove(std::move(entry2))));
  EXPECT_CALL(*entry1, GetName()).WillOnce(Return("/sys/test/path1"));

  // Mock UdevEnumerate.
  auto enumerate = std::make_unique<StrictMock<brillo::MockUdevEnumerate>>();
  EXPECT_CALL(*enumerate, AddMatchSubsystem(_)).WillOnce(Return(true));
  EXPECT_CALL(*enumerate, ScanDevices()).WillOnce(Return(true));
  EXPECT_CALL(*enumerate, GetListEntry())
      .WillOnce(Return(ByMove(std::move(entry1))));

  // Mock Udev.
  auto udev = std::make_unique<StrictMock<brillo::MockUdev>>();
  EXPECT_CALL(*udev, CreateEnumerate())
      .WillOnce(Return(ByMove(std::move(enumerate))));
  EXPECT_CALL(*udev, CreateDeviceFromSysPath(_))
      .Times(2)
      .WillRepeatedly(Invoke([](const char* sys_path) {
        // Mock UdevDevice. For mock convenience, make device node same as
        // sysfs path.
        auto device = std::make_unique<NiceMock<brillo::MockUdevDevice>>();
        ON_CALL(*device, GetDeviceNode()).WillByDefault(Return(sys_path));
        return device;
      }));

  auto udev_utils = std::make_unique<UdevUtilsImpl>(std::move(udev));
  std::unique_ptr<UdevDevice> device;
  EXPECT_TRUE(
      udev_utils->GetBlockDeviceFromDevicePath("/sys/test/path2", &device));
  EXPECT_EQ("/sys/test/path2", device->GetDeviceNode());
}

}  // namespace rmad
