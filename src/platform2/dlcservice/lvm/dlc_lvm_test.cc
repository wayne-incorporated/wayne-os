// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "dlcservice/boot/mock_boot_slot.h"
#include "dlcservice/lvm/dlc_lvm.h"
#include "dlcservice/test_utils.h"

using testing::_;
using testing::DoAll;
using testing::Return;
using testing::SetArgPointee;

namespace dlcservice {

class DlcLvmTest : public BaseTest {
 public:
  DlcLvmTest() = default;

  DlcLvmTest(const DlcLvmTest&) = delete;
  DlcLvmTest& operator=(const DlcLvmTest&) = delete;

  void SetUp() override {
    ON_CALL(*mock_boot_slot_ptr_, GetSlot())
        .WillByDefault(Return(BootSlotInterface::Slot::A));
    ON_CALL(*mock_boot_slot_ptr_, IsDeviceRemovable())
        .WillByDefault(Return(false));
    BaseTest::SetUp();
  }
};

TEST_F(DlcLvmTest, CreateDlc) {
  // Fourth DLC has `use-logical-volume` set to true.
  DlcLvm dlc(kFourthDlc);
  dlc.Initialize();

  EXPECT_CALL(*mock_lvmd_proxy_wrapper_ptr_, CreateLogicalVolumes)
      .WillOnce(Return(true));

  EXPECT_TRUE(dlc.CreateDlc(&err_));
}

TEST_F(DlcLvmTest, CreateDlcLvmFailed) {
  // Fourth DLC has `use-logical-volume` set to true.
  DlcLvm dlc(kFourthDlc);
  dlc.Initialize();

  EXPECT_CALL(*mock_lvmd_proxy_wrapper_ptr_, CreateLogicalVolumes)
      .WillOnce(Return(false));

  EXPECT_FALSE(dlc.CreateDlc(&err_));
  // The `err_` should not be nullptr if returned false.
  EXPECT_NE(err_.get(), nullptr);
}

TEST_F(DlcLvmTest, DeleteDlc) {
  // Fourth DLC has `use-logical-volume` set to true.
  DlcLvm dlc(kFourthDlc);
  dlc.Initialize();

  EXPECT_CALL(*mock_lvmd_proxy_wrapper_ptr_, RemoveLogicalVolumes)
      .WillOnce(Return(true));

  EXPECT_TRUE(dlc.DeleteInternal(&err_));
}

TEST_F(DlcLvmTest, DeleteDlcLvmFailed) {
  // Fourth DLC has `use-logical-volume` set to true.
  DlcLvm dlc(kFourthDlc);
  dlc.Initialize();

  EXPECT_CALL(*mock_lvmd_proxy_wrapper_ptr_, RemoveLogicalVolumes)
      .WillOnce(Return(false));

  EXPECT_FALSE(dlc.DeleteInternal(&err_));
  // The `err_` should not be nullptr if returned false.
  EXPECT_NE(err_.get(), nullptr);
}

TEST_F(DlcLvmTest, MountDlc) {
  // Fourth DLC has `use-logical-volume` set to true.
  DlcLvm dlc(kFourthDlc);
  dlc.Initialize();

  EXPECT_CALL(*mock_lvmd_proxy_wrapper_ptr_, GetLogicalVolumePath).Times(1);
  EXPECT_CALL(*mock_image_loader_proxy_ptr_, LoadDlc(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>("mount_point"), Return(true)));

  std::string mount_point;
  EXPECT_TRUE(dlc.MountInternal(&mount_point, &err_));
  EXPECT_EQ(mount_point, "mount_point");
}

TEST_F(DlcLvmTest, MountDlcImageLoaderFailed) {
  // Fourth DLC has `use-logical-volume` set to true.
  DlcLvm dlc(kFourthDlc);
  dlc.Initialize();

  EXPECT_CALL(*mock_lvmd_proxy_wrapper_ptr_, GetLogicalVolumePath).Times(1);
  EXPECT_CALL(*mock_image_loader_proxy_ptr_, LoadDlc(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>("mount_point"), Return(false)));

  std::string mount_point;
  EXPECT_FALSE(dlc.MountInternal(&mount_point, &err_));
  EXPECT_EQ(mount_point, "mount_point");
  EXPECT_NE(err_.get(), nullptr);
}

TEST_F(DlcLvmTest, MountDlcEmptyMountPoint) {
  // Fourth DLC has `use-logical-volume` set to true.
  DlcLvm dlc(kFourthDlc);
  dlc.Initialize();

  EXPECT_CALL(*mock_lvmd_proxy_wrapper_ptr_, GetLogicalVolumePath).Times(1);
  EXPECT_CALL(*mock_image_loader_proxy_ptr_, LoadDlc(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(""), Return(true)));

  std::string mount_point;
  EXPECT_FALSE(dlc.MountInternal(&mount_point, &err_));
  EXPECT_EQ(mount_point, "");
  EXPECT_NE(err_.get(), nullptr);
}

}  // namespace dlcservice
