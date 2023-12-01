// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/utils/sys_utils_impl.h"

#include <memory>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <brillo/file_utils.h>
#include <gtest/gtest.h>

#include "rmad/constants.h"

namespace rmad {

class SysUtilsTest : public testing::Test {
 public:
  SysUtilsTest() = default;
  ~SysUtilsTest() override = default;

 protected:
  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    sys_utils_ = std::make_unique<SysUtilsImpl>(temp_dir_.GetPath());
  }

  base::ScopedTempDir temp_dir_;
  std::unique_ptr<SysUtils> sys_utils_;
};

TEST_F(SysUtilsTest, IsPowerSourcePresent_Present) {
  // Create power supply files.
  base::FilePath supply_path =
      temp_dir_.GetPath().AppendASCII("class/power_supply/1");
  EXPECT_TRUE(base::CreateDirectory(supply_path));
  EXPECT_TRUE(base::WriteFile(supply_path.AppendASCII("type"), "USB_PD"));
  EXPECT_TRUE(base::WriteFile(supply_path.AppendASCII("online"), "1"));

  EXPECT_TRUE(sys_utils_->IsPowerSourcePresent());
}

TEST_F(SysUtilsTest, IsPowerSourcePresent_NotPresent) {
  EXPECT_FALSE(sys_utils_->IsPowerSourcePresent());
}

TEST_F(SysUtilsTest, IsPowerSourcePresent_OnBattery) {
  // Create power supply files.
  base::FilePath supply_path =
      temp_dir_.GetPath().AppendASCII("class/power_supply/1");
  EXPECT_TRUE(base::CreateDirectory(supply_path));
  EXPECT_TRUE(base::WriteFile(supply_path.AppendASCII("type"), "Battery"));
  EXPECT_TRUE(base::WriteFile(supply_path.AppendASCII("online"), "1"));

  EXPECT_FALSE(sys_utils_->IsPowerSourcePresent());
}

TEST_F(SysUtilsTest, IsPowerSourcePresent_NotOnline) {
  // Create power supply files.
  base::FilePath supply_path =
      temp_dir_.GetPath().AppendASCII("class/power_supply/1");
  EXPECT_TRUE(base::CreateDirectory(supply_path));
  EXPECT_TRUE(base::WriteFile(supply_path.AppendASCII("type"), "USB_PD"));
  EXPECT_TRUE(base::WriteFile(supply_path.AppendASCII("online"), "0"));

  EXPECT_FALSE(sys_utils_->IsPowerSourcePresent());
}

}  // namespace rmad
