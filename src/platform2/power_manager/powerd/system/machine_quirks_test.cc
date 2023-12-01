// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/machine_quirks.h"

#include <memory>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

#include "power_manager/common/fake_prefs.h"
#include "power_manager/common/power_constants.h"
#include "power_manager/common/util.h"
#include "power_manager/powerd/testing/test_environment.h"

namespace power_manager::system {

namespace {

const char sp_models[] =
    "OptiPlex 740\n"
    "ThinkPad X120e\n"
    "HP Compaq dc7900";
const char sti_models[] =
    "Compaq dc7800\n"
    "compaq dc5800\n"
    "OptiPlex 7020\n"
    "OptiPlex 9010\n"
    "OptiPlex 9020\n"
    "HP Compaq 6000 Pro\n"
    "HP Compaq 8000 Elite\n"
    "ThinkCentre M93\n"
    "ProDesk 600 G1\n"
    "Surface Pro 3\n";
}  // namespace

class MachineQuirksTest : public TestEnvironment {
 public:
  MachineQuirksTest() {
    // Create mock directories
    CHECK(temp_dir_.CreateUniqueTempDir());
    dmi_id_dir_ = temp_dir_.GetPath().Append("sys/class/dmi/id/");
    CHECK(base::CreateDirectory(dmi_id_dir_));

    // Tell machine_quirks_ what directories to use
    machine_quirks_.set_dmi_id_dir_for_test(dmi_id_dir_);

    // Set up mock pref device lists
    prefs_.SetString(kSuspendPreventionListPref, sp_models);
    prefs_.SetString(kSuspendToIdleListPref, sti_models);

    // Set up mock prefs default values
    prefs_.SetInt64(kDisableIdleSuspendPref, 0);
    prefs_.SetInt64(kSuspendToIdlePref, 0);
    prefs_.SetInt64(kHasMachineQuirksPref, 1);

    // Init machine_quirks_ with prefs
    machine_quirks_.Init(&prefs_);
  }

  MachineQuirksTest(const MachineQuirksTest&) = delete;
  MachineQuirksTest& operator=(const MachineQuirksTest&) = delete;

  ~MachineQuirksTest() override = default;

 protected:
  void CreateDmiFile(std::string name, std::string data) {
    base::FilePath file_name = base::FilePath(name);
    base::CreateTemporaryFileInDir(dmi_id_dir_, &file_name);
    ASSERT_TRUE(util::WriteFileFully(dmi_id_dir_.Append(name), data.c_str(),
                                     data.size()));
  }

  base::ScopedTempDir temp_dir_;
  base::FilePath dmi_id_dir_;
  FakePrefs prefs_;
  MachineQuirks machine_quirks_;
};

// Tests IsQuirkMatch function by inputting strings that are or aren't on the
// device lists
TEST_F(MachineQuirksTest, IsQuirkMatch) {
  std::string sp_list;
  prefs_.GetString(kSuspendPreventionListPref, &sp_list);
  EXPECT_EQ(true, machine_quirks_.IsQuirkMatch("OptiPlex 740", sp_list));
  EXPECT_EQ(true, machine_quirks_.IsQuirkMatch("HP Compaq dc7900", sp_list));
  EXPECT_EQ(false, machine_quirks_.IsQuirkMatch("OptiPlex", sp_list));

  prefs_.GetString(kSuspendToIdleListPref, &sp_list);
  EXPECT_EQ(true, machine_quirks_.IsQuirkMatch("Compaq dc7800", sp_list));
  EXPECT_EQ(true, machine_quirks_.IsQuirkMatch("Surface Pro 3", sp_list));
  EXPECT_EQ(false, machine_quirks_.IsQuirkMatch("HP Compaq dc7900", sp_list));
}

// Test that IsSuspendToIdle is true when the dmi value is a match
TEST_F(MachineQuirksTest, IsSuspendToIdleTrue) {
  CreateDmiFile("product_name", "OptiPlex 7020");
  EXPECT_EQ(true, machine_quirks_.IsSuspendToIdle());
  // Also test for the case when there is whitespace added
  CreateDmiFile("product_name", " OptiPlex 7020 ");
  EXPECT_EQ(true, machine_quirks_.IsSuspendToIdle());
}

// Test that IsSuspendToIdle is false when there is no matching dmi value
TEST_F(MachineQuirksTest, IsSuspendToIdleFalse) {
  EXPECT_EQ(false, machine_quirks_.IsSuspendToIdle());
  CreateDmiFile("product_name", "foo");
  EXPECT_EQ(false, machine_quirks_.IsSuspendToIdle());
}

// Test that IsSuspendBlocked is true when the dmi value is a match
TEST_F(MachineQuirksTest, IsSuspendBlockedTrue) {
  CreateDmiFile("product_name", "HP Compaq dc7900");
  EXPECT_EQ(true, machine_quirks_.IsSuspendBlocked());
  // Also test for the case when there is whitespace added
  CreateDmiFile("product_name", " HP Compaq dc7900 ");
  EXPECT_EQ(true, machine_quirks_.IsSuspendBlocked());
}

// Test that IsSuspendBlocked is false when there is no matching dmi value
TEST_F(MachineQuirksTest, IsSuspendBlockedFalse) {
  EXPECT_EQ(false, machine_quirks_.IsSuspendBlocked());
  CreateDmiFile("product_name", "foo");
  EXPECT_EQ(false, machine_quirks_.IsSuspendBlocked());
}

// Testing that when kHasMachineQuirksPref = 0, then no quirks are applied
TEST_F(MachineQuirksTest, MachineQuirksDisabled) {
  CreateDmiFile("product_name", "HP Compaq dc7900");
  prefs_.SetInt64(kHasMachineQuirksPref, 0);
  machine_quirks_.ApplyQuirksToPrefs();
  int64_t disable_idle_suspend_pref = 2;
  int64_t suspend_to_idle_pref = 2;
  CHECK(prefs_.GetInt64(kDisableIdleSuspendPref, &disable_idle_suspend_pref));
  CHECK(prefs_.GetInt64(kSuspendToIdlePref, &suspend_to_idle_pref));
  EXPECT_EQ(0, disable_idle_suspend_pref);
  EXPECT_EQ(0, suspend_to_idle_pref);
}

// Testing that the correct pref is set when there aren't any quirk matches
TEST_F(MachineQuirksTest, ApplyQuirksToPrefsNone) {
  machine_quirks_.ApplyQuirksToPrefs();
  int64_t disable_idle_suspend_pref = 2;
  int64_t suspend_to_idle_pref = 2;
  CHECK(prefs_.GetInt64(kDisableIdleSuspendPref, &disable_idle_suspend_pref));
  CHECK(prefs_.GetInt64(kSuspendToIdlePref, &suspend_to_idle_pref));
  EXPECT_EQ(0, disable_idle_suspend_pref);
  EXPECT_EQ(0, suspend_to_idle_pref);
}

// Testing that the correct pref is set when there's a suspend blocked match
TEST_F(MachineQuirksTest, ApplyQuirksToPrefsWhenSuspendIsBlocked) {
  CreateDmiFile("product_name", "HP Compaq dc7900");
  machine_quirks_.ApplyQuirksToPrefs();
  int64_t disable_idle_suspend_pref = 2;
  int64_t suspend_to_idle_pref = 2;

  CHECK(prefs_.GetInt64(kDisableIdleSuspendPref, &disable_idle_suspend_pref));
  CHECK(prefs_.GetInt64(kSuspendToIdlePref, &suspend_to_idle_pref));
  EXPECT_EQ(1, disable_idle_suspend_pref);
  EXPECT_EQ(0, suspend_to_idle_pref);
}

// Testing that the correct pref is set when there's a suspend to idle match
TEST_F(MachineQuirksTest, ApplyQuirksToPrefsWhenIsSuspendToIdle) {
  CreateDmiFile("product_name", "OptiPlex 7020");
  machine_quirks_.ApplyQuirksToPrefs();
  int64_t disable_idle_suspend_pref = 2;
  int64_t suspend_to_idle_pref = 2;

  CHECK(prefs_.GetInt64(kDisableIdleSuspendPref, &disable_idle_suspend_pref));
  CHECK(prefs_.GetInt64(kSuspendToIdlePref, &suspend_to_idle_pref));
  EXPECT_EQ(0, disable_idle_suspend_pref);
  EXPECT_EQ(1, suspend_to_idle_pref);
}

}  // namespace power_manager::system
