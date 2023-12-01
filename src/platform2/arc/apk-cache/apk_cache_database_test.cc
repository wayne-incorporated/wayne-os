// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/apk-cache/apk_cache_database.h"

#include <optional>
#include <string>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/time/time.h>
#include <gtest/gtest.h>
#include <sqlite3.h>

#include "arc/apk-cache/apk_cache_database_test_utils.h"
#include "arc/apk-cache/apk_cache_utils.h"

namespace apk_cache {

namespace {

constexpr char kTestSessionSource[] = "test_session";
constexpr char kTestPackageName[] = "com.example";
constexpr int64_t kTestVersionCode = 123;
constexpr int64_t kTestPackageSize = 1234;
constexpr char kTestPackageHash[] = "1234567890abcdef";
constexpr int32_t kTestPackagePriority = 0;

void CreateTestPackage(const base::FilePath& db_path) {
  Session session = {1, kTestSessionSource, base::Time::Now(),
                     kSessionStatusClosed};
  InsertSessionForTesting(db_path, session);
  FileEntry file_entry = {1,
                          kTestPackageName,
                          kTestVersionCode,
                          kFileTypeBaseApk,
                          std::nullopt,
                          kTestPackageSize,
                          std::string(kTestPackageHash),
                          base::Time::Now(),
                          kTestPackagePriority,
                          1};
  InsertFileEntryForTesting(db_path, file_entry);
}

}  // namespace

class ApkCacheDatabaseTest : public testing::Test {
 public:
  const base::FilePath& temp_path() const { return temp_dir_.GetPath(); }

 protected:
  ApkCacheDatabaseTest() = default;
  ApkCacheDatabaseTest(const ApkCacheDatabaseTest&) = delete;
  ApkCacheDatabaseTest& operator=(const ApkCacheDatabaseTest&) = delete;

  void SetUp() override { ASSERT_TRUE(temp_dir_.CreateUniqueTempDir()); }
  void TearDown() override { ASSERT_TRUE(temp_dir_.Delete()); }

 private:
  base::ScopedTempDir temp_dir_;
};

// Test create database and check integrity
TEST_F(ApkCacheDatabaseTest, CreateDatabase) {
  base::FilePath db_path = temp_path().Append(kDatabaseFile);
  ASSERT_EQ(CreateDatabaseForTesting(db_path), SQLITE_OK);
  EXPECT_TRUE(base::PathExists(db_path));

  ApkCacheDatabase db(db_path);
  EXPECT_EQ(db.Init(), SQLITE_OK);
  EXPECT_TRUE(db.CheckIntegrity());

  EXPECT_EQ(db.Close(), SQLITE_OK);
}

// Test database query
TEST_F(ApkCacheDatabaseTest, DatabaseQuery) {
  base::FilePath db_path = temp_path().Append(kDatabaseFile);
  ASSERT_EQ(CreateDatabaseForTesting(db_path), SQLITE_OK);
  EXPECT_TRUE(base::PathExists(db_path));
  CreateTestPackage(db_path);

  ApkCacheDatabase db(db_path);
  EXPECT_EQ(db.Init(), SQLITE_OK);
  EXPECT_TRUE(db.CheckIntegrity());

  // Query sessions
  auto sessions = db.GetSessions();
  ASSERT_TRUE(sessions != std::nullopt);
  EXPECT_GT((*sessions)[0].id, 0);
  EXPECT_EQ((*sessions)[0].source, std::string(kTestSessionSource));
  EXPECT_LT((*sessions)[0].timestamp, base::Time::Now() + base::Seconds(1));
  EXPECT_EQ((*sessions)[0].status, kSessionStatusClosed);

  // Query file entries
  auto file_entries = db.GetFileEntries();
  ASSERT_TRUE(file_entries != std::nullopt);
  EXPECT_GT((*file_entries)[0].id, 0);
  EXPECT_EQ((*file_entries)[0].package_name, std::string(kTestPackageName));
  EXPECT_EQ((*file_entries)[0].version_code, kTestVersionCode);
  EXPECT_EQ((*file_entries)[0].type, std::string(kFileTypeBaseApk));
  EXPECT_EQ((*file_entries)[0].attributes, std::nullopt);
  EXPECT_EQ((*file_entries)[0].size, kTestPackageSize);
  EXPECT_EQ((*file_entries)[0].hash, std::string(kTestPackageHash));
  EXPECT_LT((*file_entries)[0].access_time,
            base::Time::Now() + base::Seconds(1));
  EXPECT_EQ((*file_entries)[0].priority, kTestPackagePriority);
  EXPECT_EQ((*file_entries)[0].session_id, (*sessions)[0].id);

  EXPECT_EQ(db.Close(), SQLITE_OK);
}

// Test delete session, related files should also be deleted
TEST_F(ApkCacheDatabaseTest, DeleteSession) {
  base::FilePath db_path = temp_path().Append(kDatabaseFile);
  ASSERT_EQ(CreateDatabaseForTesting(db_path), SQLITE_OK);
  EXPECT_TRUE(base::PathExists(db_path));
  CreateTestPackage(db_path);

  ApkCacheDatabase db(db_path);
  EXPECT_EQ(db.Init(), SQLITE_OK);

  // Query sessions
  auto sessions = db.GetSessions();
  ASSERT_TRUE(sessions != std::nullopt);
  EXPECT_EQ(sessions->size(), 1);

  // Delete session
  EXPECT_TRUE(db.DeleteSession((*sessions)[0].id));

  // Session should be removed
  sessions = db.GetSessions();
  ASSERT_TRUE(sessions != std::nullopt);
  EXPECT_EQ(sessions->size(), 0);

  // File entry should also be removed
  auto file_entries = db.GetFileEntries();
  ASSERT_TRUE(file_entries != std::nullopt);
  EXPECT_EQ(file_entries->size(), 0);

  EXPECT_EQ(db.Close(), SQLITE_OK);
}

// Test delete file entry
TEST_F(ApkCacheDatabaseTest, DeleteFileEntry) {
  base::FilePath db_path = temp_path().Append(kDatabaseFile);
  ASSERT_EQ(CreateDatabaseForTesting(db_path), SQLITE_OK);
  EXPECT_TRUE(base::PathExists(db_path));
  CreateTestPackage(db_path);

  ApkCacheDatabase db(db_path);
  EXPECT_EQ(db.Init(), SQLITE_OK);

  // Query file entries
  auto file_entries = db.GetFileEntries();
  ASSERT_TRUE(file_entries != std::nullopt);
  EXPECT_EQ(file_entries->size(), 1);

  // Delete file entry
  EXPECT_TRUE(db.DeleteFileEntry((*file_entries)[0].id));

  // File entry should be removed
  file_entries = db.GetFileEntries();
  ASSERT_TRUE(file_entries != std::nullopt);
  EXPECT_EQ(file_entries->size(), 0);

  // Session should not be removed
  auto sessions = db.GetSessions();
  ASSERT_TRUE(sessions != std::nullopt);
  EXPECT_EQ(sessions->size(), 1);

  EXPECT_EQ(db.Close(), SQLITE_OK);
}

}  // namespace apk_cache
