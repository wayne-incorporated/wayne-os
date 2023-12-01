// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/common/fake_prefs.h"
#include "power_manager/common/power_constants.h"
#include "power_manager/powerd/system/suspend_freezer.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <set>
#include <string>

#include <base/containers/contains.h>
#include <base/files/file_util.h>
#include <gtest/gtest.h>
#include "power_manager/powerd/testing/test_environment.h"

namespace power_manager::system {

namespace {

const base::FilePath kTestPath("/sys/fs/cgroup/freezer/test");

// Testing abstraction that pretends to perform file actions and allows setting
// responses.
class MockSystemUtils : public SuspendFreezer::SystemUtilsInterface {
 public:
  bool PathExists(const base::FilePath& path) override { return true; }
  bool ReadFileToString(const base::FilePath& path,
                        std::string* contents) override {
    if (path == kWakeupCountPath) {
      *contents = "1";
      return true;
    }
    if (file_contents_.find(path) == file_contents_.end())
      return false;
    *contents = file_contents_[path];
    return true;
  }
  int WriteFile(const base::FilePath& path,
                const char* data,
                int size) override {
    if (file_contents_.find(path) == file_contents_.end() || permission_fail_)
      return -1;
    if (set_write_) {
      file_contents_[path] = data;
      if (strcmp(data, kFreezerStateFrozen) == 0)
        freeze_order_.push_back(path);
    }
    return size;
  }
  void GetSubDirs(const base::FilePath& root_path,
                  std::vector<base::FilePath>* dirs) override {
    if (root_path != base::FilePath(kBasePath))
      return;
    for (auto cgroup : file_contents_) {
      dirs->push_back(cgroup.first.DirName());
    }
  }

  bool set_write_;
  bool permission_fail_;
  std::map<base::FilePath, std::string> file_contents_;
  std::vector<base::FilePath> freeze_order_;
};

}  // namespace

class SuspendFreezerTest : public TestEnvironment {
 public:
  SuspendFreezerTest()
      : mock_sys_utils_(new MockSystemUtils),
        test_state_(kTestPath.Append(kStateFile)) {
    mock_sys_utils_->set_write_ = true;
    mock_sys_utils_->permission_fail_ = false;
    mock_sys_utils_->file_contents_[test_state_] = kFreezerStateThawed;
    suspend_freezer_.set_sys_utils_for_testing(mock_sys_utils_);
    suspend_freezer_.clock()->set_current_time_for_testing(
        base::TimeTicks() + base::Microseconds(1000));
    suspend_freezer_.Init(&prefs_);
  }

  ~SuspendFreezerTest() override = default;

 protected:
  FakePrefs prefs_;
  MockSystemUtils* mock_sys_utils_;
  SuspendFreezer suspend_freezer_;
  base::FilePath test_state_;
};

// Test that FreezeUserspace times out and returns failure if the state doesn't
// change.
TEST_F(SuspendFreezerTest, TestFreezeTimeout) {
  mock_sys_utils_->set_write_ = false;
  suspend_freezer_.clock()->set_time_step_for_testing(base::Seconds(5));
  EXPECT_EQ(FreezeResult::FAILURE, suspend_freezer_.FreezeUserspace(1, true));
}

// Test that FreezeUserspace and ThawUserspace write the correct state and
// return under normal operation.
TEST_F(SuspendFreezerTest, TestSuccess) {
  EXPECT_EQ(FreezeResult::SUCCESS, suspend_freezer_.FreezeUserspace(1, true));
  EXPECT_EQ(kFreezerStateFrozen, mock_sys_utils_->file_contents_[test_state_]);
  EXPECT_TRUE(suspend_freezer_.ThawUserspace());
  EXPECT_EQ(kFreezerStateThawed, mock_sys_utils_->file_contents_[test_state_]);
}

// Test that Init() will thaw processes in test cgroup (if powerd crashes and
// restarts after freezing them).
TEST_F(SuspendFreezerTest, TestReInit) {
  EXPECT_EQ(FreezeResult::SUCCESS, suspend_freezer_.FreezeUserspace(1, true));
  EXPECT_EQ(kFreezerStateFrozen, mock_sys_utils_->file_contents_[test_state_]);
  suspend_freezer_.Init(&prefs_);
  EXPECT_EQ(kFreezerStateThawed, mock_sys_utils_->file_contents_[test_state_]);
}

// Test that if multiple freezer cgroups exist, all are frozen/thawed.
TEST_F(SuspendFreezerTest, TestAll) {
  base::FilePath test1 =
      base::FilePath("/sys/fs/cgroup/freezer/test1").Append(kStateFile);
  base::FilePath test2 =
      base::FilePath("/sys/fs/cgroup/freezer/test2").Append(kStateFile);

  mock_sys_utils_->file_contents_[test1] = kFreezerStateThawed;
  mock_sys_utils_->file_contents_[test2] = kFreezerStateThawed;
  EXPECT_EQ(FreezeResult::SUCCESS, suspend_freezer_.FreezeUserspace(1, true));
  EXPECT_EQ(kFreezerStateFrozen, mock_sys_utils_->file_contents_[test_state_]);
  EXPECT_EQ(kFreezerStateFrozen, mock_sys_utils_->file_contents_[test1]);
  EXPECT_EQ(kFreezerStateFrozen, mock_sys_utils_->file_contents_[test2]);
  EXPECT_TRUE(suspend_freezer_.ThawUserspace());
  EXPECT_EQ(kFreezerStateThawed, mock_sys_utils_->file_contents_[test_state_]);
  EXPECT_EQ(kFreezerStateThawed, mock_sys_utils_->file_contents_[test1]);
  EXPECT_EQ(kFreezerStateThawed, mock_sys_utils_->file_contents_[test2]);
}

// Test that we fail properly if a root level cgroup is added that we don't have
// permission to write to.
TEST_F(SuspendFreezerTest, TestPermissionsFail) {
  mock_sys_utils_->permission_fail_ = true;
  EXPECT_EQ(FreezeResult::FAILURE, suspend_freezer_.FreezeUserspace(1, true));
}

// Test early wakeup by passing in a wakeup_count of 0 to FreezeUserspace. It
// will read back a wakeup count of 1 by default, resulting in a mismatch which
// should cancel Freeze.
TEST_F(SuspendFreezerTest, TestEarlyWakeup) {
  mock_sys_utils_->set_write_ = false;
  EXPECT_EQ(FreezeResult::CANCELED, suspend_freezer_.FreezeUserspace(0, true));
}

// Test that cgroups will freeze in the correct order based on dependencies
// specified in prefs_.
TEST_F(SuspendFreezerTest, TestOrdering) {
  std::vector<base::FilePath> test_order;
  base::FilePath test1 =
      base::FilePath("/sys/fs/cgroup/freezer/test1").Append(kStateFile);
  base::FilePath test2 =
      base::FilePath("/sys/fs/cgroup/freezer/test2").Append(kStateFile);
  base::FilePath test3 =
      base::FilePath("/sys/fs/cgroup/freezer/test3").Append(kStateFile);

  mock_sys_utils_->file_contents_[test1] = kFreezerStateThawed;
  mock_sys_utils_->file_contents_[test2] = kFreezerStateThawed;
  mock_sys_utils_->file_contents_[test3] = kFreezerStateThawed;
  prefs_.SetString(std::string(kSuspendFreezerDepsPrefix) + "test", "test3");
  prefs_.SetString(std::string(kSuspendFreezerDepsPrefix) + "test3", "test2");
  prefs_.SetString(std::string(kSuspendFreezerDepsPrefix) + "test2", "test1");
  suspend_freezer_.Init(&prefs_);
  EXPECT_EQ(FreezeResult::SUCCESS, suspend_freezer_.FreezeUserspace(1, true));
  test_order = {test_state_, test3, test2, test1};
  EXPECT_EQ(test_order, mock_sys_utils_->freeze_order_);
  EXPECT_TRUE(suspend_freezer_.ThawUserspace());

  mock_sys_utils_->freeze_order_.clear();
  mock_sys_utils_->file_contents_[test1] = kFreezerStateThawed;
  mock_sys_utils_->file_contents_[test2] = kFreezerStateThawed;
  mock_sys_utils_->file_contents_[test3] = kFreezerStateThawed;
  prefs_.SetString(std::string(kSuspendFreezerDepsPrefix) + "test", "test1");
  prefs_.SetString(std::string(kSuspendFreezerDepsPrefix) + "test1", "test2");
  prefs_.SetString(std::string(kSuspendFreezerDepsPrefix) + "test2", "test3");
  prefs_.Unset(std::string(kSuspendFreezerDepsPrefix) + "test3");
  suspend_freezer_.Init(&prefs_);
  EXPECT_EQ(FreezeResult::SUCCESS, suspend_freezer_.FreezeUserspace(1, true));
  test_order = {test_state_, test1, test2, test3};
  EXPECT_EQ(test_order, mock_sys_utils_->freeze_order_);
  EXPECT_TRUE(suspend_freezer_.ThawUserspace());

  mock_sys_utils_->freeze_order_.clear();
  mock_sys_utils_->file_contents_[test1] = kFreezerStateThawed;
  mock_sys_utils_->file_contents_[test2] = kFreezerStateThawed;
  mock_sys_utils_->file_contents_[test3] = kFreezerStateThawed;
  prefs_.SetString(std::string(kSuspendFreezerDepsPrefix) + "test", "test3");
  prefs_.SetString(std::string(kSuspendFreezerDepsPrefix) + "test3", "test1");
  prefs_.SetString(std::string(kSuspendFreezerDepsPrefix) + "test1", "test2");
  prefs_.Unset(std::string(kSuspendFreezerDepsPrefix) + "test2");
  suspend_freezer_.Init(&prefs_);
  EXPECT_EQ(FreezeResult::SUCCESS, suspend_freezer_.FreezeUserspace(1, true));
  test_order = {test_state_, test3, test1, test2};
  EXPECT_EQ(test_order, mock_sys_utils_->freeze_order_);
  EXPECT_TRUE(suspend_freezer_.ThawUserspace());
}

// Test the partial ordering of |freeze_order_| when multiple dependencies are
// included for individual cgroups.
TEST_F(SuspendFreezerTest, TestMultipleDeps) {
  base::FilePath test1 =
      base::FilePath("/sys/fs/cgroup/freezer/test1").Append(kStateFile);
  base::FilePath test2 =
      base::FilePath("/sys/fs/cgroup/freezer/test2").Append(kStateFile);
  base::FilePath test3 =
      base::FilePath("/sys/fs/cgroup/freezer/test3").Append(kStateFile);
  base::FilePath test4 =
      base::FilePath("/sys/fs/cgroup/freezer/test4").Append(kStateFile);

  mock_sys_utils_->file_contents_[test1] = kFreezerStateThawed;
  mock_sys_utils_->file_contents_[test2] = kFreezerStateThawed;
  mock_sys_utils_->file_contents_[test3] = kFreezerStateThawed;
  mock_sys_utils_->file_contents_[test4] = kFreezerStateThawed;
  prefs_.SetString(std::string(kSuspendFreezerDepsPrefix) + "test",
                   "test1\ntest2");
  prefs_.SetString(std::string(kSuspendFreezerDepsPrefix) + "test1",
                   "test3\ntest4");
  suspend_freezer_.Init(&prefs_);
  EXPECT_EQ(FreezeResult::SUCCESS, suspend_freezer_.FreezeUserspace(1, true));
  EXPECT_EQ(test_state_, mock_sys_utils_->freeze_order_[0]);
  EXPECT_TRUE(base::Contains(mock_sys_utils_->freeze_order_, test1));
  EXPECT_TRUE(base::Contains(mock_sys_utils_->freeze_order_, test2));
  EXPECT_TRUE(base::Contains(mock_sys_utils_->freeze_order_, test3));
  EXPECT_TRUE(base::Contains(mock_sys_utils_->freeze_order_, test4));

  const auto test1_it = std::find(mock_sys_utils_->freeze_order_.begin(),
                                  mock_sys_utils_->freeze_order_.end(), test1);
  EXPECT_TRUE(test1_it < std::find(mock_sys_utils_->freeze_order_.begin(),
                                   mock_sys_utils_->freeze_order_.end(),
                                   test3));
  EXPECT_TRUE(test1_it < std::find(mock_sys_utils_->freeze_order_.begin(),
                                   mock_sys_utils_->freeze_order_.end(),
                                   test4));
}

// Test that FreezeUserspace fails when there's a circular dependency chain.
TEST_F(SuspendFreezerTest, TestCircularDeps) {
  base::FilePath test1 =
      base::FilePath("/sys/fs/cgroup/freezer/test1").Append(kStateFile);
  base::FilePath test2 =
      base::FilePath("/sys/fs/cgroup/freezer/test2").Append(kStateFile);

  mock_sys_utils_->file_contents_[test1] = kFreezerStateThawed;
  mock_sys_utils_->file_contents_[test2] = kFreezerStateThawed;
  prefs_.SetString(std::string(kSuspendFreezerDepsPrefix) + "test", "test1");
  prefs_.SetString(std::string(kSuspendFreezerDepsPrefix) + "test1", "test2");
  prefs_.SetString(std::string(kSuspendFreezerDepsPrefix) + "test2", "test");
  suspend_freezer_.Init(&prefs_);
  EXPECT_EQ(FreezeResult::FAILURE, suspend_freezer_.FreezeUserspace(1, true));
  // Check that cgroups are unfrozen
  EXPECT_EQ(mock_sys_utils_->file_contents_[test_state_], kFreezerStateThawed);
  EXPECT_EQ(mock_sys_utils_->file_contents_[test1], kFreezerStateThawed);
  EXPECT_EQ(mock_sys_utils_->file_contents_[test2], kFreezerStateThawed);
}

}  // namespace power_manager::system
