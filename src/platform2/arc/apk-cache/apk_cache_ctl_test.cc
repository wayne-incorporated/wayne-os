// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/apk-cache/apk_cache_ctl_commands.h"

#include <cinttypes>
#include <iostream>
#include <sstream>
#include <string>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/stringprintf.h>
#include <gtest/gtest.h>
#include <sqlite3.h>

#include "arc/apk-cache/apk_cache_database.h"
#include "arc/apk-cache/apk_cache_database_test_utils.h"
#include "arc/apk-cache/apk_cache_utils.h"

namespace apk_cache {

namespace {

constexpr char kTestSessionSource[] = "unit_test_session_source";
constexpr int64_t kTestSessionId = 123;

constexpr int64_t kTestBaseApkId = 1234;
constexpr int64_t kTestAttachmentId = 1235;
constexpr char kTestPackageName[] = "com.package.test";
constexpr int64_t kTestVersionCode = 1234;
constexpr char kTestAttachmentType[] = "test.foo.bar";
constexpr char kTestFileContent[] = "test file content";
constexpr char kTestFileHash[] = "2Q7xZR_Z51Y-GhRQoWvXhOmn4tPfD1p5jfwb33CmSuo";
constexpr int32_t kTestPackagePriority = 100;

bool CreateSession(const base::FilePath& db_path, int64_t id, int32_t status) {
  Session session;
  session.id = id;
  session.source = kTestSessionSource;
  session.timestamp = base::Time::Now();
  session.status = status;
  return InsertSessionForTesting(db_path, session);
}

bool CreateFileEntry(const base::FilePath& db_path,
                     const base::FilePath& files_path,
                     int64_t id,
                     const std::string& package_name,
                     int64_t version_code,
                     const std::string& type) {
  FileEntry file_entry;
  file_entry.id = id;
  file_entry.package_name = package_name;
  file_entry.version_code = version_code;
  file_entry.type = type;
  file_entry.size = strlen(kTestFileContent);
  file_entry.hash = std::string(kTestFileHash);
  file_entry.access_time = base::Time::Now();
  file_entry.priority = kTestPackagePriority;
  file_entry.session_id = kTestSessionId;
  if (!InsertFileEntryForTesting(db_path, file_entry))
    return false;

  base::FilePath file_path = files_path.Append(GetFileNameById(id));
  return base::WriteFile(file_path, kTestFileContent, strlen(kTestFileContent));
}

bool CreateValidPackage(const base::FilePath& db_path,
                        const base::FilePath& files_path) {
  return CreateSession(db_path, kTestSessionId, kSessionStatusClosed) &&
         CreateFileEntry(db_path, files_path, kTestBaseApkId, kTestPackageName,
                         kTestVersionCode, kFileTypeBaseApk) &&
         CreateFileEntry(db_path, files_path, kTestAttachmentId,
                         kTestPackageName, kTestVersionCode,
                         kTestAttachmentType);
}

}  // namespace

class ApkCacheCtlTest : public testing::Test {
 public:
  const base::FilePath& temp_path() const { return temp_dir_.GetPath(); }

 protected:
  ApkCacheCtlTest() = default;

  // Not copyable or movable.
  ApkCacheCtlTest(const ApkCacheCtlTest&) = delete;
  ApkCacheCtlTest& operator=(const ApkCacheCtlTest&) = delete;

  void SetUp() override { ASSERT_TRUE(temp_dir_.CreateUniqueTempDir()); }
  void TearDown() override { ASSERT_TRUE(temp_dir_.Delete()); }

 private:
  base::ScopedTempDir temp_dir_;
};

// Command |ls| should list file entries in the cache.
TEST_F(ApkCacheCtlTest, TestLs) {
  // Create database
  base::FilePath db_path = temp_path().AppendASCII(kDatabaseFile);
  ASSERT_EQ(CreateDatabaseForTesting(db_path), SQLITE_OK);
  EXPECT_TRUE(base::PathExists(db_path));
  // Create files directory
  base::FilePath files_path = temp_path().AppendASCII(kFilesBase);
  ASSERT_TRUE(base::CreateDirectory(files_path));
  // Create valid package
  ASSERT_TRUE(CreateValidPackage(db_path, files_path));
  // Run command
  std::ostringstream os;
  ASSERT_EQ(CommandLs(temp_path(), os), ExitCode::kOk);
  // Validate output
  std::string output = os.str();
  ASSERT_NE(output.find(kTestPackageName), std::string::npos);
  ASSERT_NE(output.find(kFileTypeBaseApk), std::string::npos);
  ASSERT_NE(output.find(kTestAttachmentType), std::string::npos);
}

}  // namespace apk_cache
