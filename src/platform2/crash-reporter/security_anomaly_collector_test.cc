// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/security_anomaly_collector.h"

#include <unistd.h>

#include <string>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_split.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "crash-reporter/test_util.h"

using base::FilePath;

namespace {

// Source tree log config file name.
constexpr char kLogConfigFileName[] = "crash_reporter_logs.conf";

constexpr char kTestFilename[] = "test-security-anomaly";
constexpr char kTestCrashDirectory[] = "test-crash-directory";

constexpr int32_t kSampleWeight = 100;

constexpr char kTestSecurityAnomalyMessage[] =
    "-usr-local-abcdef\n"
    "signals\001wx-mount\002dest\001/usr/local\002\n"
    "=== Anomalous conditions ===\n"
    "/dev/sda1 /usr/local ext4 rw 0 0\n";

constexpr char kTestSecurityAnomalyBadMessage[] =
    "This is not a properly formatted message.";

constexpr char kTestSecurityAnomalyBadMetadata[] =
    "-usr-local-abcdef\n"
    "signals\003wx-mount\004dest\003/usr/local\004\n"
    "=== Anomalous conditions ===\n"
    "/dev/sda1 /usr/local ext4 rw 0 0\n";

constexpr char kTestSecurityAnomalyMetadata1[] =
    "upload_var_security_anomaly_signals=wx-mount";
constexpr char kTestSecurityAnomalyMetadata2[] =
    "upload_var_security_anomaly_dest=/usr/local";

constexpr char kTestSecurityAnomalyMessageContent[] =
    "=== Anomalous conditions ===\n"
    "/dev/sda1 /usr/local ext4 rw 0 0\n";

}  // namespace

class SecurityAnomalyCollectorMock : public SecurityAnomalyCollector {
 public:
  MOCK_METHOD(void, SetUpDBus, (), (override));
};

class SecurityAnomalyCollectorTest : public ::testing::Test {
  void SetUp() {
    EXPECT_CALL(collector_, SetUpDBus()).WillRepeatedly(testing::Return());

    collector_.Initialize(false);
    ASSERT_TRUE(scoped_temp_dir_.CreateUniqueTempDir());
    test_path_ = scoped_temp_dir_.GetPath().Append(kTestFilename);
    collector_.set_anomaly_report_path_for_testing(test_path_);

    test_crash_directory_ =
        scoped_temp_dir_.GetPath().Append(kTestCrashDirectory);
    CreateDirectory(test_crash_directory_);
    collector_.set_crash_directory_for_test(test_crash_directory_);
    collector_.set_log_config_path(
        test_util::GetTestDataPath(kLogConfigFileName,
                                   /*use_testdata=*/false)
            .value());
  }

 protected:
  SecurityAnomalyCollectorMock collector_;
  base::ScopedTempDir scoped_temp_dir_;
  FilePath test_path_;
  FilePath test_crash_directory_;
};

TEST_F(SecurityAnomalyCollectorTest, CollectOK) {
  // Collector produces an anomaly report.
  ASSERT_TRUE(test_util::CreateFile(test_path_, kTestSecurityAnomalyMessage));
  EXPECT_TRUE(collector_.Collect(kSampleWeight));
  EXPECT_FALSE(IsDirectoryEmpty(test_crash_directory_));

  FilePath metadata_file_path;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "security_anomaly.*.meta", &metadata_file_path));
  std::string metadata;
  base::ReadFileToString(metadata_file_path, &metadata);

  // We better find the metadata that we added.
  EXPECT_THAT(metadata, testing::HasSubstr(kTestSecurityAnomalyMetadata1));
  EXPECT_THAT(metadata, testing::HasSubstr(kTestSecurityAnomalyMetadata2));
  // And we should also find the weight.
  EXPECT_THAT(metadata, testing::HasSubstr("upload_var_weight=100"));

  FilePath content_file_path;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "security_anomaly.*.log", &content_file_path));
  std::string content;
  base::ReadFileToString(content_file_path, &content);
  EXPECT_STREQ(content.c_str(), kTestSecurityAnomalyMessageContent);
}

TEST_F(SecurityAnomalyCollectorTest, BadMessage) {
  // Collector does not process a badly-formatted message.
  ASSERT_TRUE(
      test_util::CreateFile(test_path_, kTestSecurityAnomalyBadMessage));
  EXPECT_FALSE(collector_.Collect(kSampleWeight));
  EXPECT_TRUE(IsDirectoryEmpty(test_crash_directory_));
}

TEST_F(SecurityAnomalyCollectorTest, BadMetadata) {
  // Collector does not process a message with incorrectly-formatted metadata.
  ASSERT_TRUE(
      test_util::CreateFile(test_path_, kTestSecurityAnomalyBadMetadata));
  EXPECT_FALSE(collector_.Collect(kSampleWeight));
  EXPECT_TRUE(IsDirectoryEmpty(test_crash_directory_));
}
