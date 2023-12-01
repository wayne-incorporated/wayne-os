// Copyright 2010 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/unclean_shutdown_collector.h"

#include <unistd.h>

#include <string>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_util.h>
#include <brillo/syslog_logging.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "crash-reporter/test_util.h"

using base::FilePath;
using ::brillo::FindLog;

class UncleanShutdownCollectorMock : public UncleanShutdownCollector {
 public:
  MOCK_METHOD(void, SetUpDBus, (), (override));
};

class UncleanShutdownCollectorTest : public ::testing::Test {
  void SetUp() {
    EXPECT_CALL(collector_, SetUpDBus()).WillRepeatedly(testing::Return());

    collector_.Initialize(false);

    ASSERT_TRUE(scoped_temp_dir_.CreateUniqueTempDir());
    test_dir_ = scoped_temp_dir_.GetPath();
    test_crash_spool_ = test_dir_.Append("crash");
    test_crash_lib_dir_ = test_dir_.Append("var_lib_crash_reporter");

    test_unclean_ = test_crash_lib_dir_.Append("unclean");
    collector_.unclean_shutdown_file_ = test_unclean_.value().c_str();

    // Set up an alternate power manager state file as well
    collector_.powerd_suspended_file_ = test_dir_.Append("suspended");

    brillo::ClearLog();
  }

 protected:
  UncleanShutdownCollectorMock collector_;
  FilePath test_unclean_;
  FilePath test_dir_;
  FilePath test_crash_spool_;
  FilePath test_crash_lib_dir_;
  base::ScopedTempDir scoped_temp_dir_;
};

TEST_F(UncleanShutdownCollectorTest, EnableWithoutParent) {
  ASSERT_TRUE(collector_.Enable());
  ASSERT_TRUE(base::PathExists(test_unclean_));
}

TEST_F(UncleanShutdownCollectorTest, EnableWithParent) {
  ASSERT_TRUE(base::CreateDirectory(test_crash_lib_dir_));
  ASSERT_TRUE(collector_.Enable());
  ASSERT_TRUE(base::PathExists(test_unclean_));
}

TEST_F(UncleanShutdownCollectorTest, EnableCannotWrite) {
  collector_.unclean_shutdown_file_ = "/bad/path";
  ASSERT_FALSE(collector_.Enable());
  ASSERT_TRUE(FindLog("Unable to create shutdown check file"));
}

TEST_F(UncleanShutdownCollectorTest, CollectTrue) {
  ASSERT_TRUE(collector_.Enable());
  ASSERT_TRUE(base::PathExists(test_unclean_));
  ASSERT_TRUE(collector_.Collect());
  ASSERT_FALSE(base::PathExists(test_unclean_));
  ASSERT_TRUE(FindLog("Last shutdown was not clean"));
}

TEST_F(UncleanShutdownCollectorTest, CollectFalse) {
  ASSERT_FALSE(collector_.Collect());
}

TEST_F(UncleanShutdownCollectorTest, CollectDeadBatterySuspended) {
  ASSERT_TRUE(collector_.Enable());
  ASSERT_TRUE(base::PathExists(test_unclean_));
  ASSERT_TRUE(test_util::CreateFile(collector_.powerd_suspended_file_, ""));
  ASSERT_FALSE(collector_.Collect());
  ASSERT_FALSE(base::PathExists(test_unclean_));
  ASSERT_FALSE(base::PathExists(collector_.powerd_suspended_file_));
  ASSERT_TRUE(FindLog("Unclean shutdown occurred while suspended."));
}

TEST_F(UncleanShutdownCollectorTest, Disable) {
  ASSERT_TRUE(collector_.Enable());
  ASSERT_TRUE(base::PathExists(test_unclean_));
  ASSERT_TRUE(collector_.Disable());
  ASSERT_FALSE(base::PathExists(test_unclean_));
  ASSERT_FALSE(collector_.Collect());
}

TEST_F(UncleanShutdownCollectorTest, DisableWhenNotEnabled) {
  ASSERT_TRUE(collector_.Disable());
}

TEST_F(UncleanShutdownCollectorTest, CantDisable) {
  ASSERT_TRUE(base::CreateDirectory(test_unclean_));
  ASSERT_TRUE(test_util::CreateFile(test_unclean_.Append("foo"), ""));
  ASSERT_FALSE(collector_.Disable());
}

TEST_F(UncleanShutdownCollectorTest, SaveVersionData) {
  ASSERT_TRUE(base::CreateDirectory(test_crash_spool_));
  ASSERT_TRUE(base::CreateDirectory(test_crash_lib_dir_));
  FilePath lsb_release = test_dir_.Append("lsb-release");
  const char kLsbContents[] =
      "CHROMEOS_RELEASE_BOARD=lumpy\n"
      "CHROMEOS_RELEASE_VERSION=6727.0.2015_01_26_0853\n"
      "CHROMEOS_RELEASE_NAME=Chromium OS\n";
  ASSERT_TRUE(test_util::CreateFile(lsb_release, kLsbContents));

  FilePath os_release = test_dir_.Append("os-release");
  const char kOsContents[] =
      "BUILD_ID=9428.0.2017_04_04_0853\n"
      "ID=chromeos\n"
      "VERSION_ID=59\n";
  ASSERT_TRUE(test_util::CreateFile(os_release, kOsContents));

  collector_.set_lsb_release_for_test(lsb_release);
  collector_.set_os_release_for_test(os_release);
  collector_.set_crash_directory_for_test(test_crash_spool_);
  collector_.set_reporter_state_directory_for_test(test_crash_lib_dir_);
  ASSERT_TRUE(collector_.SaveVersionData());

  std::string contents;
  base::ReadFileToString(test_crash_lib_dir_.Append("lsb-release"), &contents);
  ASSERT_EQ(contents, kLsbContents);

  base::ReadFileToString(test_crash_lib_dir_.Append("os-release"), &contents);
  ASSERT_EQ(contents, kOsContents);

  ASSERT_FALSE(base::PathExists(test_crash_spool_.Append("lsb-release")));
  ASSERT_FALSE(base::PathExists(test_crash_spool_.Append("os-release")));
}

TEST_F(UncleanShutdownCollectorTest, SaveVersionData_Overwrites) {
  ASSERT_TRUE(base::CreateDirectory(test_crash_spool_));
  ASSERT_TRUE(base::CreateDirectory(test_crash_lib_dir_));
  FilePath lsb_release = test_dir_.Append("lsb-release");
  const char kLongLsbContents[] =
      "CHROMEOS_RELEASE_BOARD=lumpy\n"
      "CHROMEOS_RELEASE_VERSION=6727.0.2015_01_26_0853\n"
      "CHROMEOS_RELEASE_NAME=Chromium OS\n"
      "SOME_OTHER_KEY=Some other value\n";
  ASSERT_TRUE(test_util::CreateFile(lsb_release, kLongLsbContents));

  FilePath os_release = test_dir_.Append("os-release");
  const char kOsContents[] =
      "BUILD_ID=9428.0.2017_04_04_0853\n"
      "ID=chromeos\n"
      "VERSION_ID=59\n";
  ASSERT_TRUE(test_util::CreateFile(os_release, kOsContents));

  collector_.set_lsb_release_for_test(lsb_release);
  collector_.set_os_release_for_test(os_release);
  collector_.set_crash_directory_for_test(test_crash_spool_);
  collector_.set_reporter_state_directory_for_test(test_crash_lib_dir_);
  ASSERT_TRUE(collector_.SaveVersionData());

  std::string contents;
  base::ReadFileToString(test_crash_lib_dir_.Append("lsb-release"), &contents);
  ASSERT_EQ(contents, kLongLsbContents);

  const char kShortLsbContents[] =
      "CHROMEOS_RELEASE_BOARD=lumpy\n"
      "CHROMEOS_RELEASE_VERSION=6727.0.2015_01_26_0853\n"
      "CHROMEOS_RELEASE_NAME=Chromium OS\n";
  ASSERT_TRUE(test_util::CreateFile(lsb_release, kShortLsbContents));
  ASSERT_TRUE(collector_.SaveVersionData());

  base::ReadFileToString(test_crash_lib_dir_.Append("lsb-release"), &contents);
  ASSERT_EQ(contents, kShortLsbContents);
}
