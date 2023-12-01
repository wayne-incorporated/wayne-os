// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/lockfile_checker.h"

#include <algorithm>
#include <memory>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <gtest/gtest.h>

#include "power_manager/common/util.h"
#include "power_manager/powerd/testing/test_environment.h"

namespace power_manager::system {

namespace {

// Sorts |paths| and returns a comma-joined string.
std::string JoinPaths(const std::vector<base::FilePath>& paths) {
  auto sorted = paths;
  std::sort(sorted.begin(), sorted.end());
  return util::JoinPaths(sorted, ",");
}

}  // namespace

class LockfileCheckerTest : public TestEnvironment {
 public:
  LockfileCheckerTest() {
    CHECK(temp_dir_.CreateUniqueTempDir());
    proc_dir_ = temp_dir_.GetPath().Append("proc");
    CHECK(base::CreateDirectory(proc_dir_));
    lock_dir_ = temp_dir_.GetPath().Append("lock");
    CHECK(base::CreateDirectory(lock_dir_));
  }
  LockfileCheckerTest(const LockfileCheckerTest&) = delete;
  LockfileCheckerTest& operator=(const LockfileCheckerTest&) = delete;

  ~LockfileCheckerTest() override = default;

 protected:
  // Creates and returns a LockfileChecker that looks for lockfiles in
  // |lock_dir_| and |files|, using |proc_dir_| to check whether PIDs exist.
  std::unique_ptr<LockfileChecker> CreateChecker(
      const std::vector<base::FilePath>& files) {
    auto checker = std::make_unique<LockfileChecker>(lock_dir_, files);
    checker->set_proc_dir_for_test(proc_dir_);
    return checker;
  }

  // Writes |data| to a file named |filename| in |lock_dir_|.
  base::FilePath CreateLockfile(const std::string& filename,
                                const std::string& data) {
    const base::FilePath path = lock_dir_.Append(filename);
    EXPECT_TRUE(util::WriteFileFully(path, data.c_str(), data.size()));
    return path;
  }

  // Creates a directory named |name| within |proc_dir_|.
  void CreateProcDir(const std::string& name) {
    EXPECT_TRUE(base::CreateDirectory(proc_dir_.Append(name)));
  }

  base::ScopedTempDir temp_dir_;
  base::FilePath proc_dir_;
  base::FilePath lock_dir_;
};

TEST_F(LockfileCheckerTest, NoLockfiles) {
  EXPECT_EQ("", JoinPaths(CreateChecker({})->GetValidLockfiles()));
}

TEST_F(LockfileCheckerTest, DirLockfile) {
  const base::FilePath path = CreateLockfile("foo.lock", "12");
  CreateProcDir("12");
  EXPECT_EQ(path.value(), JoinPaths(CreateChecker({})->GetValidLockfiles()));
}

TEST_F(LockfileCheckerTest, HardcodedLockfile) {
  const base::FilePath path = temp_dir_.GetPath().Append("valid.lock");
  const std::string kPid = "5";
  ASSERT_TRUE(util::WriteFileFully(path, kPid.c_str(), kPid.size()));
  CreateProcDir(kPid);

  auto checker =
      CreateChecker({temp_dir_.GetPath().Append("missing.lock"), path});
  EXPECT_EQ(path.value(), JoinPaths(checker->GetValidLockfiles()));

  // Create a second lockfile in the dir and check that it's reported as well.
  const std::string kPid2 = "8";
  const base::FilePath path2 = CreateLockfile("another.lock", kPid2);
  CreateProcDir(kPid2);
  EXPECT_EQ(JoinPaths({path, path2}), JoinPaths(checker->GetValidLockfiles()));
}

TEST_F(LockfileCheckerTest, PermitTrailingWhitespace) {
  const base::FilePath path = CreateLockfile("foo.lock", "56 \n");
  CreateProcDir("56");
  EXPECT_EQ(path.value(), JoinPaths(CreateChecker({})->GetValidLockfiles()));
}

TEST_F(LockfileCheckerTest, GarbageLockfile) {
  CreateLockfile("foo.lock", "abc");
  EXPECT_EQ("", JoinPaths(CreateChecker({})->GetValidLockfiles()));
}

TEST_F(LockfileCheckerTest, NonexistentPid) {
  CreateLockfile("foo.lock", "123");
  CreateProcDir("124");
  EXPECT_EQ("", JoinPaths(CreateChecker({})->GetValidLockfiles()));
}

}  // namespace power_manager::system
