// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "dlcservice/lvm/lvm_utils.h"

namespace dlcservice {

TEST(LvmUtilsTest, LogicalVolumeNameTest) {
  EXPECT_EQ("dlc_sample-dlc_a",
            LogicalVolumeName("sample-dlc", BootSlotInterface::Slot::A));
  EXPECT_EQ("dlc_sample-dlc_b",
            LogicalVolumeName("sample-dlc", BootSlotInterface::Slot::B));
}

}  // namespace dlcservice
