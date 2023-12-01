// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/storage/encrypted_container/logical_volume_backing_device.h"

#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <base/files/file_util.h>
#include <brillo/blkdev_utils/mock_lvm.h>
#include <brillo/blkdev_utils/lvm_device.h>

#include "cryptohome/storage/encrypted_container/backing_device.h"

using ::testing::_;
using ::testing::DoAll;

namespace cryptohome {

namespace {
constexpr char kLogicalVolumeReport[] =
    "{\"report\": [{ \"lv\": [ {\"lv_name\":\"foo\", "
    "\"vg_name\":\"stateful\"}]}]}";
}  // namespace

class LogicalVolumeBackingDeviceTest : public ::testing::Test {
 public:
  LogicalVolumeBackingDeviceTest()
      : lvm_command_runner_(std::make_shared<brillo::MockLvmCommandRunner>()),
        mock_lvm_(std::make_unique<brillo::LogicalVolumeManager>(
            lvm_command_runner_)),
        config_({.type = BackingDeviceType::kLogicalVolumeBackingDevice,
                 .name = "foo",
                 .size = 1024,
                 .logical_volume =
                     {.vg = std::make_shared<brillo::VolumeGroup>(
                          "stateful", lvm_command_runner_),
                      .thinpool = std::make_shared<brillo::Thinpool>(
                          "thinpool", "stateful", lvm_command_runner_)}}),
        backing_device_(std::make_unique<LogicalVolumeBackingDevice>(
            config_, mock_lvm_.get())) {}
  ~LogicalVolumeBackingDeviceTest() override = default;

  void ExpectLogicalVolume() {
    std::vector<std::string> thinpool_display = {
        "/sbin/lvs",      "-S",   "pool_lv!=\"\"",
        "--reportformat", "json", "stateful/" + config_.name};
    EXPECT_CALL(*lvm_command_runner_.get(), RunProcess(thinpool_display, _))
        .WillOnce(DoAll(SetArgPointee<1>(std::string(kLogicalVolumeReport)),
                        Return(true)));
  }

 protected:
  std::shared_ptr<brillo::MockLvmCommandRunner> lvm_command_runner_;
  std::unique_ptr<brillo::LogicalVolumeManager> mock_lvm_;
  BackingDeviceConfig config_;

  std::unique_ptr<BackingDevice> backing_device_;
};

TEST_F(LogicalVolumeBackingDeviceTest, LogicalVolumeDeviceSetup) {
  ExpectLogicalVolume();

  std::vector<std::string> lv_enable = {"lvchange", "-ay", "stateful/foo"};
  EXPECT_CALL(*lvm_command_runner_.get(), RunCommand(lv_enable))
      .Times(1)
      .WillOnce(Return(true));

  EXPECT_TRUE(backing_device_->Setup());
}

TEST_F(LogicalVolumeBackingDeviceTest, LogicalVolumeDeviceCreate) {
  std::vector<std::string> lv_create = {
      "lvcreate",   "--thin",           "-V", "1024M", "-n",
      config_.name, "stateful/thinpool"};
  EXPECT_CALL(*lvm_command_runner_.get(), RunCommand(lv_create))
      .Times(1)
      .WillOnce(Return(true));

  EXPECT_TRUE(backing_device_->Create());
}

TEST_F(LogicalVolumeBackingDeviceTest, LogicalVolumeDeviceTeardown) {
  ExpectLogicalVolume();

  std::vector<std::string> lv_disable = {"lvchange", "-an", "stateful/foo"};
  EXPECT_CALL(*lvm_command_runner_.get(), RunCommand(lv_disable))
      .Times(1)
      .WillOnce(Return(true));

  EXPECT_TRUE(backing_device_->Teardown());
}

TEST_F(LogicalVolumeBackingDeviceTest, LogicalVolumeDevicePurge) {
  ExpectLogicalVolume();

  std::vector<std::string> lv_disable = {"lvremove", "--force", "stateful/foo"};
  EXPECT_CALL(*lvm_command_runner_.get(), RunCommand(lv_disable))
      .Times(1)
      .WillOnce(Return(true));

  EXPECT_TRUE(backing_device_->Purge());
}

TEST_F(LogicalVolumeBackingDeviceTest, LogicalVolumeDeviceCaching) {
  // Expect logical volume object to be fetched once.
  ExpectLogicalVolume();

  std::vector<std::string> lv_enable = {"lvchange", "-ay", "stateful/foo"};
  std::vector<std::string> lv_purge = {"lvremove", "--force", "stateful/foo"};

  EXPECT_CALL(*lvm_command_runner_.get(), RunCommand(lv_enable))
      .Times(1)
      .WillOnce(Return(true));

  EXPECT_TRUE(backing_device_->Setup());
  EXPECT_EQ(backing_device_->GetPath(), base::FilePath("/dev/stateful/foo"));

  EXPECT_CALL(*lvm_command_runner_.get(), RunCommand(lv_purge))
      .Times(1)
      .WillOnce(Return(true));
  EXPECT_TRUE(backing_device_->Purge());

  // Post purge, the logical volume object will be re-fetched.
  ExpectLogicalVolume();
  EXPECT_CALL(*lvm_command_runner_.get(), RunCommand(lv_enable))
      .Times(1)
      .WillOnce(Return(true));

  EXPECT_TRUE(backing_device_->Setup());
}

}  // namespace cryptohome
