// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/apk-cache/cache_cleaner_utils.h"

#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

namespace apk_cache {

namespace {

constexpr char kTestFileContent[] = "test file content";

}  // namespace

class CacheCleanerUtilsTest : public testing::Test {
 public:
  const base::FilePath& temp_path() const { return temp_dir_.GetPath(); }

 protected:
  CacheCleanerUtilsTest() = default;

  // Not copyable or movable.
  CacheCleanerUtilsTest(const CacheCleanerUtilsTest&) = delete;
  CacheCleanerUtilsTest& operator=(const CacheCleanerUtilsTest&) = delete;

  void SetUp() override { ASSERT_TRUE(temp_dir_.CreateUniqueTempDir()); }
  void TearDown() override { ASSERT_TRUE(temp_dir_.Delete()); }

 private:
  base::ScopedTempDir temp_dir_;
};

// Files under root directory should be removed if FILES is passed. Directories
// should not be removed.
TEST_F(CacheCleanerUtilsTest, RemoveFile) {
  base::FilePath file_path = temp_path().Append("test_file");
  base::WriteFile(file_path, kTestFileContent, strlen(kTestFileContent));
  base::FilePath dir_path = temp_path().Append("test_dir");
  base::CreateDirectory(dir_path);

  EXPECT_TRUE(base::PathExists(file_path));
  EXPECT_TRUE(base::PathExists(dir_path));

  EXPECT_TRUE(RemoveUnexpectedItemsFromDir(
      temp_path(), base::FileEnumerator::FileType::FILES, {}));

  EXPECT_FALSE(base::PathExists(file_path));
  EXPECT_TRUE(base::PathExists(dir_path));
}

// Directories under root directory should be removed if DIRECTORIES is passed.
// Files should not be removed.
TEST_F(CacheCleanerUtilsTest, RemoveDirectory) {
  base::FilePath file_path = temp_path().Append("test_file");
  base::WriteFile(file_path, kTestFileContent, strlen(kTestFileContent));
  base::FilePath dir_path = temp_path().Append("test_dir");
  base::CreateDirectory(dir_path);

  EXPECT_TRUE(base::PathExists(file_path));
  EXPECT_TRUE(base::PathExists(dir_path));

  EXPECT_TRUE(RemoveUnexpectedItemsFromDir(
      temp_path(), base::FileEnumerator::FileType::DIRECTORIES, {}));

  EXPECT_TRUE(base::PathExists(file_path));
  EXPECT_FALSE(base::PathExists(dir_path));
}

// Symbolic links should be removed if SHOW_SYM_LINKS is passed.
TEST_F(CacheCleanerUtilsTest, RemoveSymbolicLink) {
  base::FilePath file_path = temp_path().Append("test_file");
  base::WriteFile(file_path, kTestFileContent, strlen(kTestFileContent));
  base::FilePath link_path = temp_path().Append("test_link");
  base::CreateSymbolicLink(file_path, link_path);

  EXPECT_TRUE(base::PathExists(file_path));
  EXPECT_TRUE(base::PathExists(link_path));

  EXPECT_TRUE(RemoveUnexpectedItemsFromDir(
      temp_path(),
      base::FileEnumerator::FileType::FILES |
          base::FileEnumerator::FileType::SHOW_SYM_LINKS,
      {}));

  EXPECT_FALSE(base::PathExists(file_path));
  EXPECT_FALSE(base::PathExists(link_path));
}

// Expected files and directories should not be removed.
TEST_F(CacheCleanerUtilsTest, NotRemoveExpected) {
  base::FilePath file_path = temp_path().Append("test_file");
  base::WriteFile(file_path, kTestFileContent, strlen(kTestFileContent));
  base::FilePath dir_path = temp_path().Append("test_dir");
  base::CreateDirectory(dir_path);

  base::FilePath expected_file_path = temp_path().Append("expected_file");
  base::WriteFile(expected_file_path, kTestFileContent,
                  strlen(kTestFileContent));
  base::FilePath expected_dir_path = temp_path().Append("expected_dir");
  base::CreateDirectory(expected_dir_path);

  EXPECT_TRUE(base::PathExists(file_path));
  EXPECT_TRUE(base::PathExists(dir_path));
  EXPECT_TRUE(base::PathExists(expected_file_path));
  EXPECT_TRUE(base::PathExists(expected_dir_path));

  EXPECT_TRUE(RemoveUnexpectedItemsFromDir(
      temp_path(),
      base::FileEnumerator::FileType::FILES |
          base::FileEnumerator::FileType::DIRECTORIES |
          base::FileEnumerator::FileType::SHOW_SYM_LINKS,
      {"expected_file", "expected_dir"}));

  EXPECT_FALSE(base::PathExists(file_path));
  EXPECT_FALSE(base::PathExists(dir_path));
  EXPECT_TRUE(base::PathExists(expected_file_path));
  EXPECT_TRUE(base::PathExists(expected_dir_path));
}

}  // namespace apk_cache
