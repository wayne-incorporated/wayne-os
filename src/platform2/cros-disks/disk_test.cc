// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/disk.h"

#include <gtest/gtest.h>

namespace cros_disks {

class DiskTest : public ::testing::Test {
 protected:
  Disk disk_;
};

TEST_F(DiskTest, GetPresentationNameForDiskWithLabel) {
  disk_.label = "My Disk";
  EXPECT_EQ(disk_.label, disk_.GetPresentationName());
}

TEST_F(DiskTest, GetPresentationNameForDiskWithLabelWithSlashes) {
  disk_.label = "This/Is/My/Disk";
  EXPECT_EQ("This_Is_My_Disk", disk_.GetPresentationName());
}

TEST_F(DiskTest, GetPresentationNameForDiskWithoutLabel) {
  EXPECT_EQ("External Drive", disk_.GetPresentationName());

  disk_.media_type = DeviceType::kUSB;
  EXPECT_EQ("USB Drive", disk_.GetPresentationName());

  disk_.media_type = DeviceType::kSD;
  EXPECT_EQ("SD Card", disk_.GetPresentationName());

  disk_.media_type = DeviceType::kOpticalDisc;
  EXPECT_EQ("Optical Disc", disk_.GetPresentationName());

  disk_.media_type = DeviceType::kMobile;
  EXPECT_EQ("Mobile Device", disk_.GetPresentationName());

  disk_.media_type = DeviceType::kDVD;
  EXPECT_EQ("DVD", disk_.GetPresentationName());
}

}  // namespace cros_disks
