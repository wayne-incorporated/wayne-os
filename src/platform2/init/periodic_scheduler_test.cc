// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "init/periodic_scheduler.h"

#include <memory>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;

namespace {

void WaitForFile(const base::FilePath& path) {
  int i = 0;
  while (!base::PathExists(path)) {
    sleep(1);
    if (i++ > 5)
      break;
  }
}

}  // namespace

class PeriodicSchedulerTest : public ::testing::Test {
 public:
  PeriodicSchedulerTest() {
    CHECK(tmpdir_.CreateUniqueTempDir());
    marker_file_ = tmpdir_.GetPath().Append("ok");
    test_process_file_ = tmpdir_.GetPath().Append("spool/cron-lite/boo");

    // Create a periodic scheduler for basic sanity testing.
    std::vector<std::string> default_cmd({"touch", marker_file_.value()});
    p = std::make_unique<PeriodicScheduler>(base::Seconds(3), base::Seconds(10),
                                            "boo", default_cmd);
    p->set_spool_dir_for_test(tmpdir_.GetPath().Append("spool"));
    p->set_check_freq_for_test(base::Seconds(1));
  }
  ~PeriodicSchedulerTest() = default;

  void SetupDefaultDirectories() {
    ASSERT_TRUE(base::CreateDirectory(tmpdir_.GetPath().Append("spool")));
    ASSERT_TRUE(
        base::CreateDirectory(tmpdir_.GetPath().Append("spool/cron-lite")));
  }

  void RunPeriodicScheduler() {
    pid_t pid = fork();
    PCHECK(pid != -1);
    if (pid != 0) {
      periodic_scheduler_pid_ = pid;
    } else {
      p->Run();
    }
  }

  void StopPeriodicScheduler() {
    EXPECT_EQ(kill(periodic_scheduler_pid_, SIGTERM), 0);
  }

  std::unique_ptr<PeriodicScheduler> p;
  pid_t periodic_scheduler_pid_;
  base::ScopedTempDir tmpdir_;
  base::FilePath marker_file_;
  base::FilePath test_process_file_;
};

TEST_F(PeriodicSchedulerTest, BasicSanity) {
  // Create a fake symbolic link instead of the spool directory.
  const base::FilePath symlink = tmpdir_.GetPath().Append("symlink");
  ASSERT_TRUE(base::CreateSymbolicLink(tmpdir_.GetPath(), symlink));

  // Run the periodic scheduler for enough time to make sure that the spool
  // directory is recreated.
  RunPeriodicScheduler();
  WaitForFile(marker_file_);
  StopPeriodicScheduler();

  // Check sanity of permissions of spool.
  EXPECT_TRUE(base::DirectoryExists(tmpdir_.GetPath().Append("spool")));
  EXPECT_TRUE(base::DirectoryExists(
      tmpdir_.GetPath().Append("spool").Append("cron-lite")));

  // Check for the existence of the file that should have been created.
  EXPECT_TRUE(base::PathExists(marker_file_));
}

TEST_F(PeriodicSchedulerTest, OldFileTest) {
  SetupDefaultDirectories();

  base::WriteFile(test_process_file_, nullptr, 0);
  base::Time old_timestamp;
  CHECK(base::Time::FromUTCString("1999-12-31 23:59", &old_timestamp));
  base::TouchFile(test_process_file_, old_timestamp, old_timestamp);

  RunPeriodicScheduler();
  WaitForFile(marker_file_);
  StopPeriodicScheduler();

  // Check the existence of the new file.
  EXPECT_TRUE(base::PathExists(marker_file_));
}

TEST_F(PeriodicSchedulerTest, EarlyKillTest) {
  SetupDefaultDirectories();

  base::WriteFile(test_process_file_, nullptr, 0);

  auto now = base::Time::Now();
  base::TouchFile(test_process_file_, now, now);

  RunPeriodicScheduler();
  sleep(2);
  StopPeriodicScheduler();

  // Check the existence of the new file.
  EXPECT_FALSE(base::PathExists(marker_file_));
}
