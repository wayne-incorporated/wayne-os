// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/missive/migration.h"

#include <array>
#include <string>
#include <unordered_set>

#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <base/strings/strcat.h>
#include <base/test/task_environment.h>
#include <base/test/test_file_util.h>
#include <brillo/syslog_logging.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "missive/analytics/metrics.h"
#include "missive/analytics/metrics_test_util.h"

namespace reporting {
namespace {

using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Return;
using ::testing::StrEq;

constexpr char kDeletionTagFile[] = ".DELETE-MISSIVE";

class MigrationTest : public ::testing::Test {
 protected:
  class ScopedMinLogLevelSetter {
   public:
    explicit ScopedMinLogLevelSetter(int level)
        : old_level_(logging::GetMinLogLevel()) {
      logging::SetMinLogLevel(level);
    }

    ~ScopedMinLogLevelSetter() { logging::SetMinLogLevel(old_level_); }

   private:
    int old_level_;
  };

  void SetUp() override {
    ASSERT_TRUE(src_.CreateUniqueTempDir());
    ASSERT_TRUE(dest_.CreateUniqueTempDir());
    deletion_tag_file_path_ = src_.GetPath().Append(kDeletionTagFile);
    brillo::LogToString(true);
    brillo::ClearLog();
  }

  void TearDown() override {
    task_environment_.RunUntilIdle();  // To make Metrics function being called.
    brillo::LogToString(false);
    brillo::ClearLog();
  }

  // Sets up files for tests in src.
  void SetUpFilesInSource() const {
    ASSERT_TRUE(base::IsDirectoryEmpty(src_.GetPath()));
    ASSERT_TRUE(base::CreateDirectory(src_.GetPath().Append("emptydir")));
    ASSERT_TRUE(base::CreateDirectory(src_.GetPath().Append("subdir0")));
    ASSERT_TRUE(
        base::WriteFile(src_.GetPath().Append("subdir0/emptyfile"), ""));
    ASSERT_TRUE(base::WriteFile(src_.GetPath().Append("subdir0/regfile"),
                                "Content in subdir0"));
    ASSERT_TRUE(base::CreateDirectory(src_.GetPath().Append("subdir1")));
    ASSERT_TRUE(
        base::WriteFile(src_.GetPath().Append("subdir1/emptyfile"), ""));
    ASSERT_TRUE(base::WriteFile(src_.GetPath().Append("subdir1/regfile"),
                                "Content in subdir1"));
    ASSERT_TRUE(base::WriteFile(src_.GetPath().Append("somefile0"),
                                "Content in somefile0"));
    ASSERT_TRUE(base::WriteFile(src_.GetPath().Append("somefile1"),
                                "Content in somefile1"));
    ASSERT_TRUE(base::WriteFile(src_.GetPath().Append("emptyfile"), ""));
  }

  // Sets up files in destination.
  void SetUpFilesInDestination() const {
    ASSERT_TRUE(base::IsDirectoryEmpty(dest_.GetPath()));
    ASSERT_TRUE(base::CreateDirectory(dest_.GetPath().Append("empty_dir")));
    ASSERT_TRUE(base::CreateDirectory(dest_.GetPath().Append("sub_dir0")));
    ASSERT_TRUE(
        base::WriteFile(dest_.GetPath().Append("sub_dir0/empty_file"), ""));
    ASSERT_TRUE(base::WriteFile(dest_.GetPath().Append("sub_dir0/reg_file"),
                                "Content in sub_dir0"));
    ASSERT_TRUE(base::CreateDirectory(dest_.GetPath().Append("sub_dir1")));
    ASSERT_TRUE(
        base::WriteFile(dest_.GetPath().Append("sub_dir1/empty_file"), ""));
    ASSERT_TRUE(base::WriteFile(dest_.GetPath().Append("sub_dir1/reg_file"),
                                "Content in sub_dir1"));
    ASSERT_TRUE(base::WriteFile(dest_.GetPath().Append("some_file0"),
                                "Content in some_file0"));
    ASSERT_TRUE(base::WriteFile(dest_.GetPath().Append("some_file1"),
                                "Content in some_file1"));
    ASSERT_TRUE(base::WriteFile(dest_.GetPath().Append("empty_file"), ""));
  }

  // Expects that only files to be migrated is in destination and nothing else
  // is in the destination dir.
  void ExpectFilesInDestination() const {
    std::unordered_set<base::FilePath> all_expected_files;
    for (const auto& f : std::array<std::string, 7>{
             "subdir0/emptyfile", "subdir0/regfile", "subdir1/emptyfile",
             "subdir1/regfile", "somefile0", "somefile1", "emptyfile"}) {
      all_expected_files.insert(dest_.GetPath().Append(f));
    }
    std::unordered_set<base::FilePath> all_expected_dirs;
    for (const auto& f :
         std::array<std::string, 3>{"subdir0", "subdir1", "emptydir"}) {
      all_expected_dirs.insert(dest_.GetPath().Append(f));
    }

    // Iterate the destination directory and examine every file and directory.
    base::FileEnumerator dir_enum(
        dest_.GetPath(), /*recursive=*/true,
        base::FileEnumerator::FILES | base::FileEnumerator::DIRECTORIES);
    for (auto full_name = dir_enum.Next(); !full_name.empty();
         full_name = dir_enum.Next()) {
      if (base::DirectoryExists(full_name)) {
        if (auto it = all_expected_dirs.find(full_name);
            it == all_expected_dirs.end()) {
          EXPECT_FALSE(true)
              << "Dir " << full_name
              << " found, which should not exist in the destination dir.";
        } else {
          all_expected_dirs.erase(it);
        }
      } else {  // regular file
        if (auto it = all_expected_files.find(full_name);
            it == all_expected_files.end()) {
          EXPECT_FALSE(true)
              << "Regular file " << full_name
              << " found, which should not exist in the destination dir.";
        } else {
          all_expected_files.erase(it);
        }
      }
    }

    // Expect all expected files were found in the destination dir.
    if (!all_expected_files.empty()) {
      std::ostringstream err_msg;
      err_msg << "Expected regular files ";
      for (const auto& f : all_expected_files) {
        err_msg << f << ", ";
      }
      err_msg.seekp(-2, std::ios_base::end);
      err_msg << " are not found.";
      EXPECT_TRUE(all_expected_files.empty()) << err_msg.str();
    }

    if (!all_expected_dirs.empty()) {
      std::ostringstream err_msg;
      err_msg << "Expected dirs ";
      for (const auto& f : all_expected_dirs) {
        err_msg << f << ", ";
      }
      err_msg.seekp(-2, std::ios_base::end);
      err_msg << " are not found.";
      EXPECT_TRUE(all_expected_dirs.empty()) << err_msg.str();
    }
  }

  // Expect a migration status being reported.
  void ExpectMigrationStatusMetrics(MigrationStatusForUma status) const {
    EXPECT_CALL(
        analytics::Metrics::TestEnvironment::GetMockMetricsLibrary(),
        SendEnumToUMA(StrEq(kMigrationStatusUmaName),
                      Eq(static_cast<int>(status)),
                      Eq(static_cast<int>(MigrationStatusForUma::kMaxValue))))
        .WillOnce(Return(true));
  }

  base::test::TaskEnvironment task_environment_;  // needed by metrics tests.
  analytics::Metrics::TestEnvironment metrics_test_environment_;
  base::ScopedTempDir src_;
  base::ScopedTempDir dest_;
  base::FilePath deletion_tag_file_path_;
};

TEST_F(MigrationTest, DestinationNotExist) {
  const auto dest_path = dest_.GetPath();
  ASSERT_TRUE(dest_.Delete());

  ExpectMigrationStatusMetrics(MigrationStatusForUma::DestinationNotExist);

  auto [dir, status] = Migrate(src_.GetPath(), dest_path);

  EXPECT_EQ(dir, src_.GetPath());
  EXPECT_EQ(status.code(), error::FAILED_PRECONDITION);
  EXPECT_THAT(
      status.error_message(),
      HasSubstr(base::StrCat({dest_path.MaybeAsASCII(), " does not exist."})));
  EXPECT_FALSE(base::PathExists(deletion_tag_file_path_));
}

TEST_F(MigrationTest, SourceNotExist) {
  const auto src_path = src_.GetPath();
  ASSERT_TRUE(src_.Delete());
  brillo::ClearLog();
  ScopedMinLogLevelSetter scoped_min_log_setter(-1);

  ExpectMigrationStatusMetrics(MigrationStatusForUma::NotNeeded);

  auto [dir, status] = Migrate(src_path, dest_.GetPath());

  EXPECT_EQ(dir, dest_.GetPath());
  EXPECT_OK(status) << status.error_message();
  EXPECT_THAT(brillo::GetLog(),
              HasSubstr(base::StrCat(
                  {"Detected empty directory or not detected ",
                   src_path.MaybeAsASCII(), ", migration not needed."})));
  EXPECT_FALSE(base::PathExists(deletion_tag_file_path_));
}

TEST_F(MigrationTest, SourceIsEmpty) {
  ASSERT_TRUE(base::IsDirectoryEmpty(src_.GetPath()));
  brillo::ClearLog();
  ScopedMinLogLevelSetter scoped_min_log_setter(-1);

  ExpectMigrationStatusMetrics(MigrationStatusForUma::NotNeeded);

  auto [dir, status] = Migrate(src_.GetPath(), dest_.GetPath());

  EXPECT_EQ(dir, dest_.GetPath());
  EXPECT_OK(status) << status.error_message();
  EXPECT_THAT(brillo::GetLog(),
              HasSubstr(base::StrCat(
                  {"Detected empty directory or not detected ",
                   src_.GetPath().MaybeAsASCII(), ", migration not needed."})));
  EXPECT_FALSE(base::PathExists(deletion_tag_file_path_));
}

TEST_F(MigrationTest, DeletionTagFileFound) {
  SetUpFilesInSource();
  ASSERT_TRUE(base::WriteFile(deletion_tag_file_path_, ""));
  brillo::ClearLog();

  ExpectMigrationStatusMetrics(MigrationStatusForUma::Success);

  auto [dir, status] = Migrate(src_.GetPath(), dest_.GetPath());

  EXPECT_EQ(dir, dest_.GetPath());
  EXPECT_OK(status) << status.error_message();
  EXPECT_THAT(
      brillo::GetLog(),
      HasSubstr(base::StrCat(
          {"Detected file ", deletion_tag_file_path_.MaybeAsASCII(),
           ", start deleting files in ", src_.GetPath().MaybeAsASCII()})));
  EXPECT_TRUE(base::IsDirectoryEmpty(src_.GetPath()));
  EXPECT_FALSE(base::PathExists(deletion_tag_file_path_));
}

TEST_F(MigrationTest, DestinationEmpty) {
  SetUpFilesInSource();
  ASSERT_TRUE(base::IsDirectoryEmpty(dest_.GetPath()));

  ExpectMigrationStatusMetrics(MigrationStatusForUma::Success);

  auto [dir, status] = Migrate(src_.GetPath(), dest_.GetPath());

  EXPECT_THAT(dir, dest_.GetPath());
  EXPECT_OK(status) << status.error_message();
  ExpectFilesInDestination();
  EXPECT_TRUE(base::IsDirectoryEmpty(src_.GetPath()));
  EXPECT_FALSE(base::PathExists(deletion_tag_file_path_));
}

TEST_F(MigrationTest, DestinationNotEmpty) {
  SetUpFilesInSource();
  SetUpFilesInDestination();

  ExpectMigrationStatusMetrics(MigrationStatusForUma::Success);

  auto [dir, status] = Migrate(src_.GetPath(), dest_.GetPath());

  EXPECT_THAT(dir, dest_.GetPath());
  EXPECT_OK(status) << status.error_message();
  EXPECT_THAT(brillo::GetLog(),
              HasSubstr(base::StrCat({dest_.GetPath().MaybeAsASCII(),
                                      " is not empty. Cleaning it up..."})));
  ExpectFilesInDestination();
  EXPECT_TRUE(base::IsDirectoryEmpty(src_.GetPath()));
  EXPECT_FALSE(base::PathExists(deletion_tag_file_path_));
}

TEST_F(MigrationTest, SrcDeletionFailsWithoutDeletionTagFile) {
  SetUpFilesInSource();
  // Make files in subdir0 undeletable.
  ASSERT_TRUE(base::MakeFileUnwritable(src_.GetPath().Append("subdir0")));

  ExpectMigrationStatusMetrics(MigrationStatusForUma::FailToDeleteSourceFiles);

  auto [dir, status] = Migrate(src_.GetPath(), dest_.GetPath());

  EXPECT_EQ(dir, dest_.GetPath());
  EXPECT_EQ(status.code(), error::INTERNAL);
  EXPECT_THAT(status.error_message(),
              HasSubstr(base::StrCat({"Failed to delete files in ",
                                      src_.GetPath().MaybeAsASCII()})));
  EXPECT_TRUE(base::PathExists(deletion_tag_file_path_));
}

TEST_F(MigrationTest, SrcDeletionFailsWithDeletionTagFile) {
  SetUpFilesInSource();
  ASSERT_TRUE(base::WriteFile(deletion_tag_file_path_, ""));
  // Make files in subdir1 undeletable.
  ASSERT_TRUE(base::MakeFileUnwritable(src_.GetPath().Append("subdir1")));

  ExpectMigrationStatusMetrics(MigrationStatusForUma::FailToDeleteSourceFiles);

  auto [dir, status] = Migrate(src_.GetPath(), dest_.GetPath());

  EXPECT_EQ(dir, dest_.GetPath());
  EXPECT_EQ(status.code(), error::INTERNAL);
  EXPECT_THAT(status.error_message(),
              HasSubstr(base::StrCat({"Failed to delete files in ",
                                      src_.GetPath().MaybeAsASCII()})));
  EXPECT_TRUE(base::PathExists(deletion_tag_file_path_));
}

TEST_F(MigrationTest, NonEmptyDestDeletionFails) {
  SetUpFilesInSource();
  SetUpFilesInDestination();
  // Make files in sub_dir0 undeletable.
  ASSERT_TRUE(base::MakeFileUnwritable(dest_.GetPath().Append("sub_dir0")));

  ExpectMigrationStatusMetrics(
      MigrationStatusForUma::FailToDeleteDestinationFiles);

  auto [dir, status] = Migrate(src_.GetPath(), dest_.GetPath());

  EXPECT_EQ(dir, src_.GetPath());
  EXPECT_EQ(status.code(), error::INTERNAL);
  EXPECT_THAT(status.error_message(),
              HasSubstr(base::StrCat({"Failed to delete files in ",
                                      dest_.GetPath().MaybeAsASCII()})));
  EXPECT_FALSE(base::PathExists(deletion_tag_file_path_));
}

TEST_F(MigrationTest, UnwritableDest) {
  SetUpFilesInSource();
  ASSERT_TRUE(base::MakeFileUnwritable(dest_.GetPath()));

  ExpectMigrationStatusMetrics(MigrationStatusForUma::FailToCopy);

  auto [dir, status] = Migrate(src_.GetPath(), dest_.GetPath());

  EXPECT_EQ(dir, src_.GetPath());
  EXPECT_EQ(status.code(), error::INTERNAL);
  EXPECT_THAT(status.error_message(),
              HasSubstr(base::StrCat({"Failed to copy files from ",
                                      src_.GetPath().MaybeAsASCII(), " to ",
                                      dest_.GetPath().MaybeAsASCII()})));
  EXPECT_FALSE(base::PathExists(deletion_tag_file_path_));
}
}  // namespace
}  // namespace reporting
