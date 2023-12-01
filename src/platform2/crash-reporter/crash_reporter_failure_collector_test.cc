// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/crash_reporter_failure_collector.h"

#include <string>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "crash-reporter/test_util.h"

using base::FilePath;

namespace {

constexpr char kLogConfigFileName[] = "crash_reporter_logs.conf";
constexpr char kTestFilename[] = "test-crash-reporter-failure";
constexpr char kTestCrashDirectory[] = "test-crash-directory";

constexpr char kTestCrashReporterFailureMessageContent[] =
    "upload_var_collector=crash-reporter-failure-collector";
constexpr char kTestCrashReporterFailureMessagePayload[] =
    "payload=crash_reporter_failure";
constexpr char kTestCrashReporterFailureLogMessages[] =
    "===/var/log/messages===";

}  // namespace

class CrashReporterFailureCollectorMock : public CrashReporterFailureCollector {
 public:
  MOCK_METHOD(void, SetUpDBus, (), (override));
};

class CrashReporterFailureCollectorTest : public ::testing::Test {
  void SetUp() {
    EXPECT_CALL(collector_, SetUpDBus()).WillRepeatedly(testing::Return());

    collector_.Initialize(false);

    ASSERT_TRUE(scoped_temp_dir_.CreateUniqueTempDir());
    test_path_ = scoped_temp_dir_.GetPath().Append(kTestFilename);
    test_crash_directory_ =
        scoped_temp_dir_.GetPath().Append(kTestCrashDirectory);
    CreateDirectory(test_crash_directory_);

    collector_.set_crash_directory_for_test(test_crash_directory_);
    collector_.set_log_config_path(
        test_util::GetTestDataPath(kLogConfigFileName, /*use_testdata=*/false)
            .value());
  }

 protected:
  CrashReporterFailureCollectorMock collector_;
  base::ScopedTempDir scoped_temp_dir_;
  FilePath test_path_;
  FilePath test_crash_directory_;
};

TEST_F(CrashReporterFailureCollectorTest, CollectOK) {
  collector_.Collect();
  EXPECT_FALSE(IsDirectoryEmpty(test_crash_directory_));
  FilePath file_path;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "crash_reporter_failure.*.meta", &file_path));
  std::string content;
  base::ReadFileToString(file_path, &content);
  EXPECT_FALSE((content.find(kTestCrashReporterFailureMessageContent) ==
                std::string::npos));
  EXPECT_FALSE((content.find(kTestCrashReporterFailureMessagePayload) ==
                std::string::npos));
}

TEST_F(CrashReporterFailureCollectorTest, CollectLog) {
  collector_.Collect();
  EXPECT_FALSE(IsDirectoryEmpty(test_crash_directory_));
  FilePath log_path;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "crash_reporter_failure.*.log", &log_path));
  std::string log_content;
  base::ReadFileToString(log_path, &log_content);
  EXPECT_FALSE((log_content.find(kTestCrashReporterFailureLogMessages) ==
                std::string::npos));

  FilePath meta_path;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "crash_reporter_failure.*.meta", &meta_path));
  std::string meta_content;
  base::ReadFileToString(meta_path, &meta_content);
  EXPECT_FALSE((meta_content.find("payload=" + log_path.BaseName().value()) ==
                std::string::npos));
}
