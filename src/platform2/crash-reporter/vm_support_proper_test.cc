// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/vm_support_proper.h"

#include <unistd.h>
#include <string>

#include <base/files/file_path.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/stringprintf.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "crash-reporter/paths.h"
#include "crash-reporter/test_util.h"

namespace {
constexpr pid_t kTestPid = 123;
constexpr char kTestPidExePath[] = "/proc/123/exe";
}  // namespace

class VmSupportProperTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_TRUE(scoped_temp_dir_.CreateUniqueTempDir());
    test_dir_ = scoped_temp_dir_.GetPath();
    paths::SetPrefixForTesting(test_dir_);

    filter_config_ = paths::Get(VmSupportProper::kFilterConfigPath);
    proc_exe_ = paths::Get(kTestPidExePath);

    base::File::Error error = base::File::FILE_OK;
    ASSERT_TRUE(base::CreateDirectoryAndGetError(proc_exe_.DirName(), &error))
        << "directory creation error: " << error;

    config_blocking_home_ =
        base::StringPrintf("filters { blocked_path: \"%s\" }",
                           paths::Get("/home").value().c_str());
  }

  void TearDown() override { paths::SetPrefixForTesting(base::FilePath()); }

  // Forward calls to PassesFilterConfig, to avoid VmSupportProper needing to
  // declare each test case as a friend individually.
  bool PassesFilterConfig(pid_t pid, std::string* out_reason) {
    return vm_support_.PassesFilterConfig(pid, out_reason);
  }

  base::FilePath test_dir_;
  base::ScopedTempDir scoped_temp_dir_;
  VmSupportProper vm_support_;
  std::string reason_;
  base::FilePath filter_config_;
  std::string config_blocking_home_;
  base::FilePath proc_exe_;
};

TEST_F(VmSupportProperTest, FilterConfigNotRequired) {
  EXPECT_TRUE(PassesFilterConfig(kTestPid, &reason_));
  EXPECT_THAT(reason_, testing::HasSubstr("failed to read"));
}

TEST_F(VmSupportProperTest, FilterConfigMayBeInvalid) {
  EXPECT_TRUE(test_util::CreateFile(filter_config_, "junk"));

  EXPECT_TRUE(PassesFilterConfig(kTestPid, &reason_));
  EXPECT_THAT(reason_, testing::HasSubstr("failed to parse"));
}

TEST_F(VmSupportProperTest, EmptyFilterConfigPermitsAll) {
  EXPECT_TRUE(test_util::CreateFile(filter_config_, ""));
  EXPECT_TRUE(
      base::CreateSymbolicLink(paths::Get("/home/chronos/myprog"), proc_exe_));

  EXPECT_TRUE(PassesFilterConfig(kTestPid, &reason_));
}

TEST_F(VmSupportProperTest, EmptyFilterPermitsAll) {
  EXPECT_TRUE(test_util::CreateFile(filter_config_, "filters {}"));
  EXPECT_TRUE(
      base::CreateSymbolicLink(paths::Get("/home/chronos/myprog"), proc_exe_));

  EXPECT_TRUE(PassesFilterConfig(kTestPid, &reason_));
}

TEST_F(VmSupportProperTest, BlockedPathsAreNotPermitted) {
  EXPECT_TRUE(test_util::CreateFile(filter_config_, config_blocking_home_));
  EXPECT_TRUE(
      base::CreateSymbolicLink(paths::Get("/home/chronos/myprog"), proc_exe_));

  EXPECT_FALSE(PassesFilterConfig(kTestPid, &reason_));
  EXPECT_THAT(reason_, testing::HasSubstr("/home are blocked"));
}

TEST_F(VmSupportProperTest, OtherPathsArePermitted) {
  EXPECT_TRUE(test_util::CreateFile(filter_config_, config_blocking_home_));
  EXPECT_TRUE(base::CreateSymbolicLink(paths::Get("/bin/bash"), proc_exe_));

  EXPECT_TRUE(PassesFilterConfig(kTestPid, &reason_));
}
