// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/selinux_violation_collector.h"

#include <unistd.h>

#include <string>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "crash-reporter/test_util.h"

using base::FilePath;

namespace {

// Source tree log config file name.
constexpr char kLogConfigFileName[] = "crash_reporter_logs.conf";

constexpr char kTestFilename[] = "test-selinux-violation";
constexpr char kTestCrashDirectory[] = "test-crash-directory";

constexpr char TestSELinuxViolationMessage[] =
    "sssss-selinux-init\n"
    "comm\001init\002scontext\001context1\002\n"
    "SELINUX VIOLATION TRIGGERED FOR init AT context1.\n";

constexpr char TestSELinuxViolationMessageContent[] =
    "SELINUX VIOLATION TRIGGERED FOR init AT context1.\n";

constexpr char TestSELinuxViolationMessageWithComm[] =
    "sssss-selinux-init\n"
    "comm\001init\002scontext\001context1\002\n"
    "SELINUX VIOLATION TRIGGERED FOR comm=\"init\" AT context1.\n";

constexpr char TestSELinuxViolationMessageWithPid[] =
    "sssss-selinux-init\n"
    "comm\001init\002scontext\001context1\002\n"
    "SELINUX VIOLATION TRIGGERED FOR pid=1234 AT context1.\n";

constexpr char TestSELinuxViolationMessageWithPidAndComm[] =
    "sssss-selinux-init\n"
    "comm\001init\002scontext\001context1\002\n"
    "SELINUX VIOLATION TRIGGERED FOR pid=1234 comm=\"init\" AT context1.\n";

constexpr char TestSELinuxViolationMessageWithCommContent[] =
    "SELINUX VIOLATION TRIGGERED FOR comm=\"init\" AT context1.\n";

constexpr char TestSELinuxViolationMessageWithPidContent[] =
    "SELINUX VIOLATION TRIGGERED FOR pid=1234 AT context1.\n";

constexpr char TestSELinuxViolationMessageWithPidAndCommContent[] =
    "SELINUX VIOLATION TRIGGERED FOR pid=1234 comm=\"init\" AT context1.\n";

constexpr char TestSELinuxViolationMessageWithInvalidComm[] =
    "sssss-selinux-init\n"
    "comm\001init\002scontext\001context1\002\n"
    "SELINUX VIOLATION TRIGGERED FOR comm=\"../etc/passwd💩\" AT context1.\n";

constexpr char TestSELinuxViolationMessageWithLongComm[] =
    "sssss-selinux-init\n"
    "comm\001init\002scontext\001context1\002\n"
    "comm=\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\""
    " AT context1.\n";

constexpr char TestSELinuxViolationMessageWithNonTerminatedComm[] =
    "sssss-selinux-init\n"
    "comm\001init\002scontext\001context1\002\n"
    "comm=\"aaaa AT context1.\n";

}  // namespace

class SELinuxViolationCollectorMock : public SELinuxViolationCollector {
 public:
  MOCK_METHOD(void, SetUpDBus, (), (override));
};

class SELinuxViolationCollectorTest : public ::testing::Test {
  void SetUp() {
    EXPECT_CALL(collector_, SetUpDBus()).WillRepeatedly(testing::Return());

    collector_.Initialize(false);
    ASSERT_TRUE(scoped_temp_dir_.CreateUniqueTempDir());
    test_path_ = scoped_temp_dir_.GetPath().Append(kTestFilename);
    collector_.set_violation_report_path_for_testing(test_path_);

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
  SELinuxViolationCollectorMock collector_;
  base::ScopedTempDir scoped_temp_dir_;
  FilePath test_path_;
  FilePath test_crash_directory_;
};

TEST_F(SELinuxViolationCollectorTest, CollectOK) {
  // Collector produces a violation report.
  ASSERT_TRUE(test_util::CreateFile(test_path_, TestSELinuxViolationMessage));
  EXPECT_TRUE(collector_.Collect(100));
  EXPECT_FALSE(IsDirectoryEmpty(test_crash_directory_));
  FilePath meta_path;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "selinux_violation.*.meta", &meta_path));

  // Meta file contains proper weight.
  std::string meta_content;
  base::ReadFileToString(meta_path, &meta_content);
  EXPECT_THAT(meta_content, testing::HasSubstr("upload_var_weight=100\n"));

  FilePath log_file_path;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "selinux_violation.*.log", &log_file_path));
  std::string content;
  base::ReadFileToString(log_file_path, &content);
  EXPECT_STREQ(content.c_str(), TestSELinuxViolationMessageContent);
}

TEST_F(SELinuxViolationCollectorTest, CollectOKWithComm) {
  // Collector produces a violation report named using the "comm" key.
  ASSERT_TRUE(
      test_util::CreateFile(test_path_, TestSELinuxViolationMessageWithComm));
  EXPECT_TRUE(collector_.Collect(100));
  EXPECT_FALSE(IsDirectoryEmpty(test_crash_directory_));
  EXPECT_TRUE(test_util::DirectoryHasFileWithPatternAndContents(
      test_crash_directory_, "selinux_violation_init.*.meta",
      "sig=sssss-selinux-init"));

  FilePath file_path;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "selinux_violation_init.*.log", &file_path));
  std::string content;
  base::ReadFileToString(file_path, &content);
  EXPECT_STREQ(content.c_str(), TestSELinuxViolationMessageWithCommContent);
}

TEST_F(SELinuxViolationCollectorTest, CollectOKWithPid) {
  // Collector produces a violation report named using the "pid" key.
  ASSERT_TRUE(
      test_util::CreateFile(test_path_, TestSELinuxViolationMessageWithPid));
  EXPECT_TRUE(collector_.Collect(100));
  EXPECT_FALSE(IsDirectoryEmpty(test_crash_directory_));
  EXPECT_TRUE(test_util::DirectoryHasFileWithPatternAndContents(
      test_crash_directory_, "selinux_violation.*.1234.meta",
      "sig=sssss-selinux-init"));

  FilePath file_path;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "selinux_violation.*.1234.log", &file_path));
  std::string content;
  base::ReadFileToString(file_path, &content);
  EXPECT_STREQ(content.c_str(), TestSELinuxViolationMessageWithPidContent);
}

TEST_F(SELinuxViolationCollectorTest, CollectOKWithPidAndComm) {
  // Collector produces a violation report named using "pid" and "comm" keys.
  ASSERT_TRUE(test_util::CreateFile(test_path_,
                                    TestSELinuxViolationMessageWithPidAndComm));
  EXPECT_TRUE(collector_.Collect(100));
  EXPECT_FALSE(IsDirectoryEmpty(test_crash_directory_));
  EXPECT_TRUE(test_util::DirectoryHasFileWithPatternAndContents(
      test_crash_directory_, "selinux_violation_init.*.1234.meta",
      "sig=sssss-selinux-init"));

  FilePath file_path;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "selinux_violation_init.*.1234.log", &file_path));
  std::string content;
  base::ReadFileToString(file_path, &content);
  EXPECT_STREQ(content.c_str(),
               TestSELinuxViolationMessageWithPidAndCommContent);
}

TEST_F(SELinuxViolationCollectorTest, CollectWithInvalidComm) {
  // Collector properly sanitizes an invalid "comm" key
  ASSERT_TRUE(test_util::CreateFile(
      test_path_, TestSELinuxViolationMessageWithInvalidComm));
  EXPECT_TRUE(collector_.Collect(100));
  EXPECT_FALSE(IsDirectoryEmpty(test_crash_directory_));
  EXPECT_TRUE(test_util::DirectoryHasFileWithPatternAndContents(
      test_crash_directory_, "selinux_violation____etc_passwd____.*.meta",
      "sig=sssss-selinux-init"));

  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "selinux_violation____etc_passwd____.*.log",
      nullptr));
}

TEST_F(SELinuxViolationCollectorTest, CollectWithLongComm) {
  // Collector properly shortens a long "comm" key
  ASSERT_TRUE(test_util::CreateFile(test_path_,
                                    TestSELinuxViolationMessageWithLongComm));
  EXPECT_TRUE(collector_.Collect(100));
  EXPECT_FALSE(IsDirectoryEmpty(test_crash_directory_));
  std::string as =
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

  EXPECT_TRUE(test_util::DirectoryHasFileWithPatternAndContents(
      test_crash_directory_, "selinux_violation_" + as + ".*.meta",
      "sig=sssss-selinux-init"));
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "selinux_violation_" + as + ".*.log", nullptr));
}

TEST_F(SELinuxViolationCollectorTest, CollectWithNonTerminatedComm) {
  // Collector properly shortens a long "comm" key
  ASSERT_TRUE(test_util::CreateFile(
      test_path_, TestSELinuxViolationMessageWithNonTerminatedComm));
  EXPECT_TRUE(collector_.Collect(100));
  EXPECT_FALSE(IsDirectoryEmpty(test_crash_directory_));

  EXPECT_TRUE(test_util::DirectoryHasFileWithPatternAndContents(
      test_crash_directory_, "selinux_violation_aaaa_AT_context1__.*.meta",
      "sig=sssss-selinux-init"));

  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "selinux_violation_aaaa_AT_context1__.*.log",
      nullptr));
}

TEST_F(SELinuxViolationCollectorTest, CollectSample) {
  // Collector produces a violation report.
  ASSERT_TRUE(test_util::CreateFile(test_path_, TestSELinuxViolationMessage));
  EXPECT_TRUE(collector_.Collect(100));
  EXPECT_FALSE(IsDirectoryEmpty(test_crash_directory_));
  EXPECT_TRUE(test_util::DirectoryHasFileWithPatternAndContents(
      test_crash_directory_, "selinux_violation.*.meta",
      "sig=sssss-selinux-init"));
  FilePath file_path;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "selinux_violation.*.log", &file_path));
  std::string content;
  base::ReadFileToString(file_path, &content);
  EXPECT_STREQ(content.c_str(), TestSELinuxViolationMessageContent);
}

TEST_F(SELinuxViolationCollectorTest, FailureReportDoesNotExist) {
  // SELinux violation report file doesn't exist.
  EXPECT_TRUE(collector_.Collect(100));
  EXPECT_TRUE(IsDirectoryEmpty(test_crash_directory_));
}

TEST_F(SELinuxViolationCollectorTest, EmptyFailureReport) {
  // SELinux violation report file exists, but doesn't have the expected
  // contents.
  ASSERT_TRUE(test_util::CreateFile(test_path_, ""));
  EXPECT_TRUE(collector_.Collect(100));
  EXPECT_TRUE(IsDirectoryEmpty(test_crash_directory_));
}
