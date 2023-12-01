// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/executor/utils/file.h"

#include <cstdint>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_piece.h>
#include <base/test/test_file_util.h>
#include <base/time/time.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace diagnostics {
namespace {
using ::testing::AllOf;
using ::testing::Ge;
using ::testing::Le;

TEST(FileUtilsDirectTest, GetFileCreationTime) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  const auto dir_path = temp_dir.GetPath();
  ASSERT_TRUE(base::DirectoryExists(dir_path));

  base::FilePath file_path;
  const auto before_time = base::Time::NowFromSystemTime();
  ASSERT_TRUE(base::CreateTemporaryFileInDir(dir_path, &file_path));
  const auto after_time = base::Time::NowFromSystemTime();

  base::Time creation_time;
  ASSERT_TRUE(GetCreationTime(file_path, creation_time));
  // Because the conversion from statx_timestamp to base::Time involves floating
  // point roundoff, we give 1 second breathing space. The main point is to
  // check the file creation time obtained is reasonable. After all, an accurate
  // check would require rewriting the logic to get creation time in the test.
  EXPECT_THAT(creation_time, AllOf(Ge(before_time - base::Seconds(1)),
                                   Le(after_time + base::Seconds(1))));
}

class ReadFilePartUtilsTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    ASSERT_TRUE(base::DirectoryExists(temp_dir_.GetPath()));
    ASSERT_TRUE(
        base::CreateTemporaryFileInDir(temp_dir_.GetPath(), &temp_file_path_));
  }

  const base::FilePath& temp_file_path() const { return temp_file_path_; }

  const base::FilePath& temp_dir_path() const { return temp_dir_.GetPath(); }

 private:
  base::ScopedTempDir temp_dir_;
  base::FilePath temp_file_path_;
};

TEST_F(ReadFilePartUtilsTest, ReadEmptyFileReturnEmpty) {
  EXPECT_EQ(ReadFilePart(temp_file_path(), 0u, 5u), "");
}

TEST_F(ReadFilePartUtilsTest, ReadNormalFileReturnReadContent) {
  constexpr base::StringPiece kFileContent = "0123456789";
  constexpr uint64_t kNonZeroBegin = 2u;
  constexpr uint64_t kSize = 5u;

  ASSERT_TRUE(base::WriteFile(temp_file_path(), kFileContent));
  EXPECT_EQ(ReadFilePart(temp_file_path(), kNonZeroBegin, kSize),
            kFileContent.substr(kNonZeroBegin, kSize));
}

TEST_F(ReadFilePartUtilsTest, ReadBeyondEOFReturnContentUntilEOF) {
  constexpr base::StringPiece kFileContent = "0123456789";

  ASSERT_TRUE(base::WriteFile(temp_file_path(), kFileContent));
  EXPECT_EQ(ReadFilePart(temp_file_path(), 0u, kFileContent.size() + 1u),
            kFileContent);
}

TEST_F(ReadFilePartUtilsTest, DontProvideSizeReturnContentUntilEOF) {
  constexpr base::StringPiece kFileContent = "0123456789";

  ASSERT_TRUE(base::WriteFile(temp_file_path(), kFileContent));
  EXPECT_EQ(ReadFilePart(temp_file_path(), 0u, std::nullopt), kFileContent);
}

TEST_F(ReadFilePartUtilsTest, ReadZeroSizeReturnEmpty) {
  ASSERT_TRUE(base::WriteFile(temp_file_path(), "0123456789"));
  EXPECT_EQ(ReadFilePart(temp_file_path(), 0u, 0u), "");
}

TEST_F(ReadFilePartUtilsTest, FileOpenFailReturnNullopt) {
  // Make the file unreadable to cause failure to open the file.
  ASSERT_TRUE(base::MakeFileUnreadable(temp_file_path()));
  EXPECT_EQ(ReadFilePart(temp_file_path(), 0u, 5u), std::nullopt);
}

TEST_F(ReadFilePartUtilsTest, BeginLargerThanFileSizeReturnNullopt) {
  ASSERT_TRUE(base::WriteFile(temp_file_path(), "1"));
  EXPECT_EQ(ReadFilePart(temp_file_path(), 2u, 5u), std::nullopt);
}

TEST_F(ReadFilePartUtilsTest, ReadDirectoryReturnNullopt) {
  EXPECT_EQ(ReadFilePart(temp_dir_path(), 0u, 5u), std::nullopt);
}
}  // namespace
}  // namespace diagnostics
