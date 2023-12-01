// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/ephemeral_crash_collector.h"

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <string>

#include "crash-reporter/paths.h"
#include "crash-reporter/test_util.h"

namespace {

constexpr char kTestCrashFileName[] = "test_crash";
constexpr char kTestCrashFileContents[] = "Not a real crash.";

}  // namespace

class EphemeralCrashCollectorTest : public testing::Test {
 private:
  void SetUp() override {
    ASSERT_TRUE(scoped_temp_dir_.CreateUniqueTempDir());
    dest_dir_ = scoped_temp_dir_.GetPath().Append("crash_dest");
    src_dir_ = scoped_temp_dir_.GetPath().Append("crash_src");
    CreateDirectory(dest_dir_);
    CreateDirectory(src_dir_);
    paths::SetPrefixForTesting(scoped_temp_dir_.GetPath());
  }

  void TearDown() override { paths::SetPrefixForTesting(base::FilePath()); }

 protected:
  void SetUpTestDirectories() {
    collector_.source_directories_ = {src_dir_};
    collector_.set_crash_directory_for_test(dest_dir_);
  }

  void ExpectOobeComplete() {
    ASSERT_TRUE(
        test_util::CreateFile(paths::Get(paths::kOobeCompletePath), "1"));
  }

  void ExpectCrashReportsParsed() {
    ASSERT_TRUE(test_util::CreateFile(src_dir_.Append(kTestCrashFileName),
                                      kTestCrashFileContents));
    EXPECT_TRUE(collector_.Collect());
    EXPECT_FALSE(base::PathExists(src_dir_));
  }

  void CheckPreserveAcrossClobberPaths() {
    EXPECT_EQ(collector_.source_directories_.size(), 1);
    EXPECT_EQ(collector_.source_directories_[0],
              base::FilePath(paths::kSystemRunCrashDirectory));
    EXPECT_EQ(collector_.system_crash_path_,
              base::FilePath(paths::kEncryptedRebootVaultCrashDirectory));
  }

  void CheckRegularCollectorPaths() {
    EXPECT_EQ(collector_.source_directories_.size(), 2);
    EXPECT_EQ(collector_.source_directories_[0],
              base::FilePath(paths::kSystemRunCrashDirectory));
    EXPECT_EQ(collector_.source_directories_[1],
              base::FilePath(paths::kEncryptedRebootVaultCrashDirectory));

    EXPECT_EQ(collector_.system_crash_path_,
              base::FilePath(paths::kSystemCrashDirectory));
  }

  base::ScopedTempDir scoped_temp_dir_;
  base::FilePath dest_dir_, src_dir_;
  EphemeralCrashCollector collector_;
};

TEST_F(EphemeralCrashCollectorTest, PreserveAcrossClobberPathsTest) {
  collector_.Initialize(/*preserve_across_clobber=*/true);
  CheckPreserveAcrossClobberPaths();
}

TEST_F(EphemeralCrashCollectorTest, CheckRegularCollectorPathsTest) {
  collector_.Initialize(/*preserve_across_clobber=*/false);
  CheckRegularCollectorPaths();
}

TEST_F(EphemeralCrashCollectorTest, CollectOk) {
  ExpectOobeComplete();
  collector_.Initialize(/*preserve_across_clobber=*/false);
  SetUpTestDirectories();

  ExpectCrashReportsParsed();

  std::string content;
  base::FilePath destination_crash_file = dest_dir_.Append(kTestCrashFileName);
  EXPECT_TRUE(base::PathExists(destination_crash_file));
  base::ReadFileToString(destination_crash_file, &content);
  EXPECT_STREQ(content.c_str(), kTestCrashFileContents);
}

TEST_F(EphemeralCrashCollectorTest, NoOobeCollectOk) {
  collector_.Initialize(/*preserve_across_clobber=*/false);
  SetUpTestDirectories();

  ExpectCrashReportsParsed();

  std::string content;
  base::FilePath destination_crash_file = dest_dir_.Append(kTestCrashFileName);

  EXPECT_TRUE(base::PathExists(destination_crash_file));
  base::ReadFileToString(destination_crash_file, &content);
  EXPECT_STREQ(content.c_str(), kTestCrashFileContents);
}

TEST_F(EphemeralCrashCollectorTest, NoSkipConsentDefault) {
  ExpectOobeComplete();
  collector_.Initialize(/*preserve_across_clobber=*/false);
  EXPECT_FALSE(collector_.SkipConsent());
}

TEST_F(EphemeralCrashCollectorTest, PreserveAcrossClobberSkipConsent) {
  ExpectOobeComplete();
  collector_.Initialize(/*preserve_across_clobber=*/true);
  EXPECT_TRUE(collector_.SkipConsent());
}

TEST_F(EphemeralCrashCollectorTest, NoOobeSkipConsent) {
  // No ExpectOobeComplete.
  collector_.Initialize(/*preserve_across_clobber=*/false);
  EXPECT_TRUE(collector_.SkipConsent());
}
