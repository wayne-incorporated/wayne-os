// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "dlcservice/boot/boot_slot.h"
#include "dlcservice/dlc_base.h"
#include "dlcservice/prefs.h"
#include "dlcservice/system_state.h"
#include "dlcservice/test_utils.h"
#include "dlcservice/utils.h"

using base::FilePath;
using std::string;

namespace dlcservice {

class PrefsTest : public BaseTest {};

TEST_F(PrefsTest, DlcBaseCreateAndDelete) {
  auto active_boot_slot = SystemState::Get()->active_boot_slot();
  Prefs prefs(DlcBase("id"), active_boot_slot);
  string key = "key";
  EXPECT_TRUE(prefs.Create(key));
  EXPECT_TRUE(prefs.Exists(key));
  Prefs prefs_non_dlcbase(JoinPaths(SystemState::Get()->dlc_prefs_dir(), "id",
                                    BootSlot::ToString(active_boot_slot)));
  EXPECT_TRUE(prefs_non_dlcbase.Exists(key));
}

TEST_F(PrefsTest, CreateAndDelete) {
  Prefs prefs(FilePath(SystemState::Get()->prefs_dir()));
  string key = "key";
  EXPECT_TRUE(prefs.Create(key));
  EXPECT_TRUE(prefs.Exists(key));
  EXPECT_TRUE(prefs.Delete(key));
  EXPECT_FALSE(prefs.Exists(key));
}

TEST_F(PrefsTest, SetAndGetThenDelete) {
  Prefs prefs(FilePath(SystemState::Get()->prefs_dir()));
  string key = "key", value = "value";
  EXPECT_TRUE(prefs.SetKey(key, value));
  string actual_value;
  EXPECT_TRUE(prefs.GetKey(key, &actual_value));
  EXPECT_EQ(value, actual_value);
  EXPECT_TRUE(prefs.Delete(key));
  EXPECT_FALSE(prefs.Exists(key));
}

TEST_F(PrefsTest, RepeatedSet) {
  Prefs prefs(FilePath(SystemState::Get()->prefs_dir()));
  string key = "key", value = "value";
  EXPECT_TRUE(prefs.SetKey(key, value));
  EXPECT_TRUE(prefs.SetKey(key, value));
}

}  // namespace dlcservice
