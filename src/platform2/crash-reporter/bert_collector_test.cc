// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/bert_collector.h"

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <brillo/syslog_logging.h>
#include <fcntl.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "crash-reporter/test_util.h"

using base::FilePath;
using brillo::FindLog;

namespace {

constexpr char kACPITableDirectory[] = "sys/firmware/acpi/tables";

}  // namespace

class BERTCollectorMock : public BERTCollector {
 public:
  MOCK_METHOD(void, SetUpDBus, (), (override));
};

class BERTCollectorTest : public ::testing::Test {
 protected:
  BERTCollectorMock collector_;
  FilePath test_dir_;
  base::ScopedTempDir scoped_temp_dir_;

  void PrepareBertDataTest(bool good_data) {
    constexpr char data[] = "Create BERT File for testing";
    FilePath testberttable_path = collector_.acpitable_path_.Append("BERT");
    FilePath testbertdata_path = collector_.acpitable_path_.Append("data/BERT");

    ASSERT_TRUE(test_util::CreateFile(testbertdata_path, data));

    if (!good_data) {
      ASSERT_TRUE(test_util::CreateFile(testberttable_path, data));
    } else {
      // Dummy test values.
      const struct acpi_table_bert bert_tab_test = {
          {'B', 'E', 'R', 'T'},
          48,
          'A',
          'D',
          "OEMID",
          "TABLEID",
          0xFFFFFFFF,
          "ACP",
          0xEEEEEEEE,
          sizeof(data),
          0x000000000001234,
      };
      ASSERT_EQ(sizeof(struct acpi_table_bert),
                base::WriteFile(testberttable_path,
                                reinterpret_cast<const char*>(&bert_tab_test),
                                sizeof(struct acpi_table_bert)));
    }
  }

 public:
  void SetUp() override {
    EXPECT_CALL(collector_, SetUpDBus()).WillRepeatedly(testing::Return());

    collector_.Initialize(false);
    ASSERT_TRUE(scoped_temp_dir_.CreateUniqueTempDir());
    test_dir_ = scoped_temp_dir_.GetPath();

    collector_.set_crash_directory_for_test(test_dir_);
    collector_.acpitable_path_ = test_dir_.Append(kACPITableDirectory);
  }
};

TEST_F(BERTCollectorTest, TestNoBERTData) {
  ASSERT_FALSE(collector_.Collect(/*use_saved_lsb=*/true));
  EXPECT_EQ(collector_.get_bytes_written(), 0);
}

TEST_F(BERTCollectorTest, TestBadBERTData) {
  PrepareBertDataTest(false);
  ASSERT_FALSE(collector_.Collect(/*use_saved_lsb=*/true));
  ASSERT_TRUE(FindLog("(handling)"));
  ASSERT_TRUE(FindLog("Bad data in BERT table"));
  EXPECT_EQ(collector_.get_bytes_written(), 0);
}

TEST_F(BERTCollectorTest, TestGoodBERTData) {
  PrepareBertDataTest(true);
  logging::SetMinLogLevel(-3);
  ASSERT_TRUE(collector_.Collect(/*use_saved_lsb=*/true));
  ASSERT_TRUE(FindLog("(handling)"));
  ASSERT_TRUE(FindLog("Stored BERT dump"));
  EXPECT_GT(collector_.get_bytes_written(), 0);
  EXPECT_TRUE(test_util::DirectoryHasFileWithPatternAndContents(
      test_dir_, "bert_error.*.meta", "upload_var_collector=bert"));
  EXPECT_TRUE(test_util::DirectoryHasFileWithPatternAndContents(
      scoped_temp_dir_.GetPath(), "bert_error.*.meta", "sig=bert_error\n"));
}

class BERTCollectorSavedLsbTest : public BERTCollectorTest,
                                  public ::testing::WithParamInterface<bool> {};

TEST_P(BERTCollectorSavedLsbTest, UsesSavedLsb) {
  FilePath lsb_release = scoped_temp_dir_.GetPath().Append("lsb-release");
  collector_.set_lsb_release_for_test(lsb_release);
  const char kLsbContents[] =
      "CHROMEOS_RELEASE_BOARD=lumpy\n"
      "CHROMEOS_RELEASE_VERSION=6727.0.2015_01_26_0853\n"
      "CHROMEOS_RELEASE_NAME=Chromium OS\n"
      "CHROMEOS_RELEASE_CHROME_MILESTONE=82\n"
      "CHROMEOS_RELEASE_TRACK=testimage-channel\n"
      "CHROMEOS_RELEASE_DESCRIPTION=6727.0.2015_01_26_0853 (Test Build - foo)";
  ASSERT_TRUE(test_util::CreateFile(lsb_release, kLsbContents));

  FilePath saved_lsb_dir =
      scoped_temp_dir_.GetPath().Append("crash-reporter-state");
  ASSERT_TRUE(base::CreateDirectory(saved_lsb_dir));
  collector_.set_reporter_state_directory_for_test(saved_lsb_dir);

  const char kSavedLsbContents[] =
      "CHROMEOS_RELEASE_BOARD=lumpy\n"
      "CHROMEOS_RELEASE_VERSION=12345.0.2015_01_26_0853\n"
      "CHROMEOS_RELEASE_NAME=Chromium OS\n"
      "CHROMEOS_RELEASE_CHROME_MILESTONE=81\n"
      "CHROMEOS_RELEASE_TRACK=beta-channel\n"
      "CHROMEOS_RELEASE_DESCRIPTION=12345.0.2015_01_26_0853 (Test Build - foo)";
  base::FilePath saved_lsb = saved_lsb_dir.Append("lsb-release");
  ASSERT_TRUE(test_util::CreateFile(saved_lsb, kSavedLsbContents));

  PrepareBertDataTest(true);
  ASSERT_TRUE(collector_.Collect(/*use_saved_lsb=*/GetParam()));

  if (GetParam()) {
    EXPECT_TRUE(test_util::DirectoryHasFileWithPatternAndContents(
        scoped_temp_dir_.GetPath(), "*.meta", "ver=12345.0.2015_01_26_0853\n"));
  } else {
    EXPECT_TRUE(test_util::DirectoryHasFileWithPatternAndContents(
        scoped_temp_dir_.GetPath(), "*.meta", "ver=6727.0.2015_01_26_0853\n"));
  }
}

INSTANTIATE_TEST_SUITE_P(BERTCollectorSavedLsbTest,
                         BERTCollectorSavedLsbTest,
                         testing::Bool());
