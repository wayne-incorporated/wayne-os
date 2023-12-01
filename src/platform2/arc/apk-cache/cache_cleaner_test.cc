// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/apk-cache/cache_cleaner.h"

#include <set>
#include <string>
#include <vector>

#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <brillo/files/file_util.h>
#include <gtest/gtest.h>

namespace apk_cache {

namespace {

constexpr char kPackage0[] = "com.example.package0";
constexpr char kPackage1[] = "com.example.package1";
constexpr int kObbVersion = 1;

bool CreateFile(const base::FilePath& file_path) {
  return base::WriteFile(file_path, "", 0) == 0;
}

bool DeleteFile(const base::FilePath& file_path) {
  return brillo::DeleteFile(file_path);
}

bool CreateDir(const base::FilePath& dir_path) {
  return base::CreateDirectory(dir_path);
}

std::string GetApkFileName(const std::string& package_name) {
  return package_name + kApkExtension;
}

std::string GetMainObbFileName(const std::string& package_name, int version) {
  return base::StringPrintf("%s%d.%s%s", kMainObbPrefix, version,
                            package_name.c_str(), kObbExtension);
}

std::string GetPatchObbFileName(const std::string& package_name, int version) {
  return base::StringPrintf("%s%d.%s%s", kPatchObbPrefix, version,
                            package_name.c_str(), kObbExtension);
}

std::string TimeToString(const base::Time& time) {
  base::Time::Exploded exploded_time;
  time.UTCExplode(&exploded_time);
  // We can't use base::Time::operator<< here because the ARC cache app writes
  // access time into JSON file following the defined time format
  // that is different from what operator<< provides.
  return base::StringPrintf(
      "%04d-%02d-%02d %02d:%02d:%02d.%03d", exploded_time.year,
      exploded_time.month, exploded_time.day_of_month, exploded_time.hour,
      exploded_time.minute, exploded_time.second, exploded_time.millisecond);
}

bool WriteAttributes(const base::FilePath& dir_path,
                     const std::string& package_name,
                     const base::Time& time) {
  const std::string json_content = base::StringPrintf(
      "{\n"
      "  \"attributes\": {\n"
      "    \"package_name\": \"%s\",\n"
      "    \"atime\": \"%s\"\n"
      "  }\n"
      "}",
      package_name.c_str(), TimeToString(time).c_str());

  const int written_bytes = base::WriteFile(
      dir_path.Append(kAttrJson), json_content.c_str(), json_content.length());
  return written_bytes == json_content.length();
}

bool CreateValidPackage(const base::FilePath& cache_root_path,
                        const std::string& package_name) {
  const base::FilePath package_path = cache_root_path.Append(package_name);
  return CreateDir(package_path) &&
         CreateFile(package_path.Append(GetApkFileName(package_name))) &&
         CreateFile(package_path.Append(
             GetMainObbFileName(package_name, kObbVersion))) &&
         CreateFile(package_path.Append(
             GetPatchObbFileName(package_name, kObbVersion))) &&
         WriteAttributes(package_path, package_name, base::Time::Now());
}

void VerifyCache(const base::FilePath& cache_root_path,
                 const std::set<std::string>& expected_package_name_set) {
  {
    base::FileEnumerator files(
        cache_root_path, false /* recursive */,
        base::FileEnumerator::FILES | base::FileEnumerator::SHOW_SYM_LINKS);
    base::FilePath unnecessary_file_path = files.Next();
    if (!unnecessary_file_path.empty())
      FAIL() << "Cache root should not contain any files but it contains "
             << unnecessary_file_path.value();
  }

  {
    base::FileEnumerator dirs(cache_root_path, false /* recursive */,
                              base::FileEnumerator::DIRECTORIES |
                                  base::FileEnumerator::SHOW_SYM_LINKS);
    std::set<std::string> available_package_name_set;

    for (base::FilePath dir_path = dirs.Next(); !dir_path.empty();
         dir_path = dirs.Next()) {
      available_package_name_set.insert(dir_path.BaseName().value());
    }

    EXPECT_EQ(available_package_name_set, expected_package_name_set);
  }
}

}  // namespace

class CacheCleanerTest : public testing::Test {
 public:
  const base::FilePath& temp_path() const { return temp_dir_.GetPath(); }

 protected:
  CacheCleanerTest() = default;
  CacheCleanerTest(const CacheCleanerTest&) = delete;
  CacheCleanerTest& operator=(const CacheCleanerTest&) = delete;

  void SetUp() override { ASSERT_TRUE(temp_dir_.CreateUniqueTempDir()); }
  void TearDown() override { ASSERT_TRUE(temp_dir_.Delete()); }

 private:
  base::ScopedTempDir temp_dir_;
};

// Creates 2 valid packages and checks that none of them is deleted.
TEST_F(CacheCleanerTest, ValidPackage) {
  ASSERT_TRUE(CreateValidPackage(temp_path(), kPackage0));
  ASSERT_TRUE(CreateValidPackage(temp_path(), kPackage1));

  EXPECT_TRUE(Clean(temp_path()));

  VerifyCache(temp_path(), {kPackage0, kPackage1});
}

// Checks that absence of main OBB file does not lead to the deletion.
TEST_F(CacheCleanerTest, NoMainObb) {
  ASSERT_TRUE(CreateValidPackage(temp_path(), kPackage0));
  ASSERT_TRUE(apk_cache::DeleteFile(temp_path().Append(kPackage0).Append(
      GetMainObbFileName(kPackage0, kObbVersion))));

  EXPECT_TRUE(Clean(temp_path()));

  VerifyCache(temp_path(), {kPackage0});
}

// Checks that absence of patch OBB file does not lead to the deletion.
TEST_F(CacheCleanerTest, NoPatchObb) {
  ASSERT_TRUE(CreateValidPackage(temp_path(), kPackage0));
  ASSERT_TRUE(apk_cache::DeleteFile(temp_path().Append(kPackage0).Append(
      GetPatchObbFileName(kPackage0, kObbVersion))));

  EXPECT_TRUE(Clean(temp_path()));

  VerifyCache(temp_path(), {kPackage0});
}

// Checks that the files in cache root are deleted.
TEST_F(CacheCleanerTest, OddFileInRoot) {
  ASSERT_TRUE(CreateFile(temp_path().Append("odd.file.1")));
  ASSERT_TRUE(CreateFile(temp_path().Append("odd.file.2")));

  EXPECT_TRUE(Clean(temp_path()));

  VerifyCache(temp_path(), {});
}

// Checks that empty package directory is deleted.
TEST_F(CacheCleanerTest, EmptyPackage) {
  ASSERT_TRUE(CreateDir(temp_path().Append(kPackage0)));

  EXPECT_TRUE(Clean(temp_path()));

  VerifyCache(temp_path(), {});
}

// No attr.json must lead to the package removal.
TEST_F(CacheCleanerTest, NoAttrJson) {
  ASSERT_TRUE(CreateValidPackage(temp_path(), kPackage0));
  ASSERT_TRUE(
      apk_cache::DeleteFile(temp_path().Append(kPackage0).Append(kAttrJson)));

  EXPECT_TRUE(Clean(temp_path()));

  VerifyCache(temp_path(), {});
}

// No APK file leads to the package removal.
TEST_F(CacheCleanerTest, NoApk) {
  ASSERT_TRUE(CreateValidPackage(temp_path(), kPackage0));
  ASSERT_TRUE(apk_cache::DeleteFile(
      temp_path().Append(kPackage0).Append(GetApkFileName(kPackage0))));

  EXPECT_TRUE(Clean(temp_path()));

  VerifyCache(temp_path(), {});
}

// If there are 2 or more main OBB files in the package, it must be deleted.
TEST_F(CacheCleanerTest, ExtraMainObbFile) {
  ASSERT_TRUE(CreateValidPackage(temp_path(), kPackage0));
  ASSERT_TRUE(CreateFile(
      temp_path().Append(kPackage0).Append(GetMainObbFileName(kPackage0, 99))));

  EXPECT_TRUE(Clean(temp_path()));

  VerifyCache(temp_path(), {});
}

// If there are 2 or more patch OBB files in the package, it must be deleted.
TEST_F(CacheCleanerTest, ExtraPatchObbFile) {
  ASSERT_TRUE(CreateValidPackage(temp_path(), kPackage0));
  ASSERT_TRUE(CreateFile(temp_path().Append(kPackage0).Append(
      GetPatchObbFileName(kPackage0, 99))));

  EXPECT_TRUE(Clean(temp_path()));

  VerifyCache(temp_path(), {});
}

// If package contains any odd file, the package is to be deleted.
TEST_F(CacheCleanerTest, ExtraRandomFile) {
  ASSERT_TRUE(CreateValidPackage(temp_path(), kPackage0));
  ASSERT_TRUE(CreateFile(temp_path().Append(kPackage0).Append("blabla.file")));

  EXPECT_TRUE(Clean(temp_path()));

  VerifyCache(temp_path(), {});
}

// If package contains any odd dir, the package is to be deleted.
TEST_F(CacheCleanerTest, ExtraRandomDir) {
  ASSERT_TRUE(CreateValidPackage(temp_path(), kPackage0));
  ASSERT_TRUE(CreateDir(temp_path().Append(kPackage0).Append("blabla.dir")));

  EXPECT_TRUE(Clean(temp_path()));

  VerifyCache(temp_path(), {});
}

// If the name of the APK does not match com.example.package.name.apk pattern,
// then the package must be deleted.
TEST_F(CacheCleanerTest, ApkNameMismatch) {
  ASSERT_TRUE(CreateValidPackage(temp_path(), kPackage0));

  ASSERT_TRUE(apk_cache::DeleteFile(
      temp_path().Append(kPackage0).Append(GetApkFileName(kPackage0))));
  ASSERT_TRUE(CreateFile(
      temp_path().Append(kPackage0).Append(GetApkFileName("blabla"))));

  EXPECT_TRUE(Clean(temp_path()));

  VerifyCache(temp_path(), {});
}

// If the name of the main OBB does not match
// main.123.com.example.package.name.obb pattern, then the package must
// be deleted.
TEST_F(CacheCleanerTest, MainObbNameMismatch) {
  ASSERT_TRUE(CreateValidPackage(temp_path(), kPackage0));

  ASSERT_TRUE(apk_cache::DeleteFile(temp_path().Append(kPackage0).Append(
      GetMainObbFileName(kPackage0, kObbVersion))));
  ASSERT_TRUE(CreateFile(temp_path().Append(kPackage0).Append(
      GetMainObbFileName("blabla", kObbVersion))));

  EXPECT_TRUE(Clean(temp_path()));

  VerifyCache(temp_path(), {});
}

// If the name of the main OBB does not match
// patch.123.com.example.package.name.obb pattern, then the package must
// be deleted.
TEST_F(CacheCleanerTest, PatchObbNameMismatch) {
  ASSERT_TRUE(CreateValidPackage(temp_path(), kPackage0));

  ASSERT_TRUE(apk_cache::DeleteFile(temp_path().Append(kPackage0).Append(
      GetPatchObbFileName(kPackage0, kObbVersion))));
  ASSERT_TRUE(CreateFile(temp_path().Append(kPackage0).Append(
      GetPatchObbFileName("blabla", kObbVersion))));

  EXPECT_TRUE(Clean(temp_path()));

  VerifyCache(temp_path(), {});
}

// Verify that expired package is deleted.
TEST_F(CacheCleanerTest, Outdated) {
  // Package0 is expired. Should be deleted.
  ASSERT_TRUE(CreateValidPackage(temp_path(), kPackage0));
  base::Time atime_0 = base::Time::Now() - (kValidityPeriod + base::Days(1));
  WriteAttributes(temp_path().Append(kPackage0), kPackage0, atime_0);

  // Package1 is 1 more day before expire. Should not be deleted.
  ASSERT_TRUE(CreateValidPackage(temp_path(), kPackage1));
  base::Time atime_1 = base::Time::Now() - (kValidityPeriod - base::Days(1));
  WriteAttributes(temp_path().Append(kPackage1), kPackage1, atime_1);

  EXPECT_TRUE(Clean(temp_path()));

  VerifyCache(temp_path(), {kPackage1});
}

// Check that symbolic links are deleted.
TEST_F(CacheCleanerTest, Symlink) {
  base::ScopedTempDir temp_dir_1;
  ASSERT_TRUE(temp_dir_1.CreateUniqueTempDir());

  // Create symlink to a file in the cache root.
  const base::FilePath symlink_file_target_path =
      temp_dir_1.GetPath().Append("symlink-target-file");
  ASSERT_TRUE(CreateFile(symlink_file_target_path));
  ASSERT_TRUE(CreateSymbolicLink(symlink_file_target_path,
                                 temp_path().Append("symlink-file")));

  // Create symlink to the valid package directory in the cache root.
  // We don't follow symlinks and they must be removed from the cache root.
  const base::FilePath symlink_dir_target_path =
      temp_dir_1.GetPath().Append(kPackage0);
  ASSERT_TRUE(CreateValidPackage(temp_dir_1.GetPath(), kPackage0));
  ASSERT_TRUE(CreateSymbolicLink(symlink_dir_target_path,
                                 temp_path().Append(kPackage0)));

  // Create symlink in the package.
  ASSERT_TRUE(CreateValidPackage(temp_path(), kPackage1));
  ASSERT_TRUE(
      CreateSymbolicLink(symlink_file_target_path,
                         temp_path().Append(kPackage1).Append("symlink")));

  EXPECT_TRUE(Clean(temp_path()));

  VerifyCache(temp_path(), {});
  EXPECT_TRUE(base::PathExists(symlink_file_target_path));
  EXPECT_TRUE(base::DirectoryExists(symlink_dir_target_path));
}

// Verify that deletion of the a package or file does not lead to
// the deletion of the valid package.
TEST_F(CacheCleanerTest, Combined) {
  ASSERT_TRUE(CreateValidPackage(temp_path(), kPackage0));

  ASSERT_TRUE(CreateValidPackage(temp_path(), kPackage1));
  base::Time atime = base::Time::Now() - (kValidityPeriod + base::Days(1));
  WriteAttributes(temp_path().Append(kPackage1), kPackage1, atime);

  ASSERT_TRUE(CreateFile(temp_path().Append("odd.file")));

  EXPECT_TRUE(Clean(temp_path()));

  VerifyCache(temp_path(), {kPackage0});
}

}  // namespace apk_cache
